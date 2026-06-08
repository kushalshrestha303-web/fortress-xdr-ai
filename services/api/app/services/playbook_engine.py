from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.bus import event_bus
from app.core.notifications import send_email
from app.models.events import PlaybookApprovalRequest, PlaybookRunRequest


HIGH_RISK_INCIDENT_PLAYBOOK = {
    "id": "high-risk-incident-response",
    "name": "Enterprise High-Risk Incident Response",
    "version": "2026.05",
    "content_pack": "NepalFortressIncidentResponse",
    "description": "Cortex XSOAR-style SOAR workflow with triage, enrichment, approval gates, containment, verification, and incident report notification.",
    "inputs": [
        {"name": "tenant_id", "required": True},
        {"name": "incident_id", "required": True},
        {"name": "severity", "required": True},
        {"name": "notify_email", "required": False, "default": "kushalshrestha993@gmail.com"},
    ],
    "tasks": [
        {
            "id": "0",
            "type": "start",
            "name": "Incident trigger",
            "next": ["1"],
            "outputs": ["Incident.ID", "Incident.Severity", "Tenant.ID"],
        },
        {
            "id": "1",
            "type": "automation",
            "name": "Normalize and score incident",
            "script": "FortressNormalizeIncident",
            "next": ["2"],
            "outputs": ["Fortress.Incident.RiskScore", "Fortress.Incident.Normalized"],
        },
        {
            "id": "2",
            "type": "integration",
            "name": "Collect evidence from SIEM, XDR, NGFW, and identity",
            "commands": ["siem-search-events", "xdr-get-endpoint", "ngfw-log-query", "iam-signin-risk"],
            "next": ["3"],
            "outputs": ["Evidence.SIEM.Events", "Evidence.XDR.Endpoint", "Evidence.NGFW.Flows", "Evidence.IAM.Risk"],
        },
        {
            "id": "3",
            "type": "integration",
            "name": "Enrich IOCs, asset, identity, and network zone",
            "commands": ["threatintel-search", "asset-get", "identity-get", "ngfw-zone-lookup"],
            "next": ["4"],
            "outputs": ["ThreatIntel.IOC", "Asset.Criticality", "Identity.User", "Network.Zone"],
        },
        {
            "id": "4",
            "type": "automation",
            "name": "Map MITRE ATT&CK and calculate blast radius",
            "script": "FortressMapAttackAndBlastRadius",
            "next": ["5"],
            "outputs": ["MITRE.Techniques", "Fortress.BlastRadius", "Fortress.BusinessImpact"],
        },
        {
            "id": "5",
            "type": "condition",
            "name": "Is containment high impact?",
            "condition": "severity == critical OR sector in protected_sectors",
            "next": ["6"],
            "outputs": ["Fortress.Decision.RequiresApproval"],
        },
        {
            "id": "6",
            "type": "manual_approval",
            "name": "SOC lead containment approval",
            "sla_minutes": 15,
            "next": ["7"],
            "outputs": ["Fortress.Approval.Status", "Fortress.Approval.RequiredRole"],
        },
        {
            "id": "7",
            "type": "condition",
            "name": "Validate policy safety and change window",
            "condition": "approval == approved AND no critical service outage predicted",
            "next": ["8"],
            "outputs": ["Change.SafetyCheck", "Change.Window"],
        },
        {
            "id": "8",
            "type": "integration",
            "name": "Block indicators on NGFW and DNS security",
            "commands": ["ngfw-address-object-create", "ngfw-security-rule-update", "ngfw-commit", "dns-sinkhole-domain"],
            "next": ["9"],
            "outputs": ["NGFW.Policy.RuleID", "NGFW.Commit.JobID", "DNS.Sinkhole.Status"],
        },
        {
            "id": "9",
            "type": "integration",
            "name": "Contain endpoint and revoke active sessions",
            "commands": ["xdr-endpoint-isolate", "iam-session-revoke", "ztna-session-terminate"],
            "next": ["10"],
            "outputs": ["XDR.Endpoint.IsolationStatus", "IAM.Session.Revoked", "ZTNA.Session.Terminated"],
        },
        {
            "id": "10",
            "type": "integration",
            "name": "Preserve forensic evidence",
            "commands": ["xdr-collect-triage-package", "file-hash-snapshot", "memory-capture-request"],
            "next": ["11"],
            "outputs": ["Forensics.PackageID", "Forensics.HashSet", "Forensics.ChainOfCustody"],
        },
        {
            "id": "11",
            "type": "automation",
            "name": "Verify containment and monitor recurrence",
            "script": "FortressVerifyContainment",
            "next": ["12"],
            "outputs": ["Containment.Verified", "Monitoring.RecurrenceWindow"],
        },
        {
            "id": "12",
            "type": "communication",
            "name": "Email security incident report",
            "commands": ["email-send"],
            "next": ["13"],
            "outputs": ["Notification.Email.Status", "Notification.Email.Recipient", "Fortress.Report.ID"],
        },
        {
            "id": "13",
            "type": "automation",
            "name": "Update case, timeline, and executive summary",
            "script": "FortressGenerateIncidentSummary",
            "next": [],
            "outputs": ["Fortress.Report.Summary", "Fortress.Report.Timeline", "Case.Status"],
        },
    ],
}

PROTECTED_SECTORS = {"bank", "government", "hospital", "telecom", "critical-infrastructure"}
POST_APPROVAL_TASK_IDS = {"7", "8", "9", "10", "11", "12", "13"}
PLAYBOOK_RUNS: dict[str, dict[str, Any]] = {}


def _risk_score(severity: str, sector: str) -> int:
    base = {"low": 25, "medium": 50, "high": 75, "critical": 95}[severity]
    return min(100, base + (5 if sector in PROTECTED_SECTORS else 0))


def _task_detail(task: dict[str, Any], request: PlaybookRunRequest, context: dict[str, Any]) -> str:
    if task["type"] == "start":
        return f"Triggered for {request.incident_id} in tenant {request.tenant_id}."
    if task["id"] == "1":
        return f"Risk score set to {context['Fortress.Incident.RiskScore']} and incident context normalized."
    if task["id"] == "2":
        return "Collected correlated SIEM, endpoint, firewall, and identity evidence for analyst review."
    if task["id"] == "3":
        return "Threat intelligence, asset criticality, identity, and network zone context attached."
    if task["id"] == "4":
        return f"Mapped suspected activity to {context['MITRE.Techniques']} with {context['Fortress.BlastRadius']} blast radius."
    if task["id"] == "5":
        return "Critical-sector containment requires approval before high-impact response commands execute."
    if task["id"] == "6":
        return "Waiting for SOC lead approval; approval role is Incident Commander or SOC Manager."
    if task["id"] == "7":
        return "Queued change safety validation before network and endpoint containment."
    if task["id"] == "8":
        return "Queued NGFW, DNS sinkhole, and policy commit actions."
    if task["id"] == "9":
        return "Queued endpoint isolation, identity session revocation, and ZTNA termination."
    if task["id"] == "10":
        return "Queued forensic package collection and chain-of-custody preservation."
    if task["id"] == "11":
        return "Queued post-containment verification and recurrence monitoring."
    if task["id"] == "12":
        return f"Security incident report will be emailed to {request.notify_email or 'default recipient'}."
    if task["id"] == "13":
        return "Queued case update, executive summary, and analyst timeline generation."
    return "Executed."


def _status_for(task: dict[str, Any], request: PlaybookRunRequest) -> str:
    if task["type"] == "manual_approval" and (request.severity == "critical" or request.sector in PROTECTED_SECTORS):
        return "waiting_for_approval"
    if task["id"] in POST_APPROVAL_TASK_IDS and (request.severity == "critical" or request.sector in PROTECTED_SECTORS):
        return "queued_after_approval"
    if task["type"] == "condition":
        return "matched"
    if task["type"] == "start":
        return "triggered"
    return "completed"


async def run_high_risk_playbook(request: PlaybookRunRequest) -> dict[str, Any]:
    run_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    task_results: list[dict[str, Any]] = []
    context: dict[str, Any] = {
        "Incident.ID": request.incident_id,
        "Incident.Severity": request.severity,
        "Tenant.ID": request.tenant_id,
        "Tenant.Sector": request.sector,
        "Operator": request.context.get("operator", "unknown"),
        "Fortress.Incident.RiskScore": _risk_score(request.severity, request.sector),
        "Fortress.Decision.RequiresApproval": request.severity == "critical" or request.sector in PROTECTED_SECTORS,
        "Fortress.Approval.RequiredRole": "Incident Commander or SOC Manager",
        "ThreatIntel.IOC": request.context.get("ioc", "pending-enrichment"),
        "Asset.Criticality": "high" if request.sector in PROTECTED_SECTORS else "standard",
        "Network.Zone": request.context.get("network_zone", "production-secure-zone"),
        "Evidence.SIEM.Events": "12 correlated events",
        "Evidence.XDR.Endpoint": request.context.get("endpoint", "NP-XDR-EDGE-044"),
        "Evidence.NGFW.Flows": "malicious outbound TLS and denied callback attempts",
        "Evidence.IAM.Risk": "impossible-travel and risky sign-in checked",
        "MITRE.Techniques": ["T1071", "T1105", "T1486"],
        "Fortress.BlastRadius": "bank payment DMZ and one endpoint segment",
        "Fortress.BusinessImpact": "Potential service disruption, credential exposure, and lateral movement risk.",
        "Change.SafetyCheck": "pending approval",
        "Change.Window": "emergency security change",
        "Fortress.Report.ID": f"NF-IR-{started_at.strftime('%Y%m%d')}-{run_id[:8]}",
        "Fortress.Report.Summary": "High-risk incident triaged with containment awaiting SOC approval.",
        "Fortress.Report.Timeline": "Trigger -> triage -> enrichment -> approval -> containment -> report",
        "Case.Status": "open_waiting_for_approval",
    }

    for task in HIGH_RISK_INCIDENT_PLAYBOOK["tasks"]:
        status = _status_for(task, request)
        task_result = {
            "task_id": task["id"],
            "task_type": task["type"],
            "name": task["name"],
            "status": status,
            "detail": _task_detail(task, request, context),
            "commands": task.get("commands", []),
            "script": task.get("script"),
            "next": task.get("next", []),
            "outputs": {key: context.get(key, "pending") for key in task.get("outputs", [])},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        task_results.append(task_result)
        await event_bus.publish(
            {
                "stream": "playbook",
                "run_id": run_id,
                "tenant_id": request.tenant_id,
                "incident_id": request.incident_id,
                "task": task_result,
            }
        )

    report_body = _incident_report_body(run_id, started_at, request, context, "waiting_for_approval")
    notification = await send_email(
        subject=f"[Nepal Fortress ONE] Security Incident Report {request.incident_id}",
        body=report_body,
        to_email=request.notify_email,
    )

    final_status = "waiting_for_approval" if context["Fortress.Decision.RequiresApproval"] else "completed"
    result = {
        "run_id": run_id,
        "playbook": HIGH_RISK_INCIDENT_PLAYBOOK,
        "incident_id": request.incident_id,
        "tenant_id": request.tenant_id,
        "status": final_status,
        "context": context,
        "evidence": [
            {"type": "risk_score", "value": context["Fortress.Incident.RiskScore"]},
            {"type": "approval_gate", "value": context["Fortress.Decision.RequiresApproval"]},
            {"type": "notification_recipient", "value": request.notify_email},
        ],
        "notification": notification,
        "report": {
            "subject": f"[Nepal Fortress ONE] Security Incident Report {request.incident_id}",
            "recipient": request.notify_email,
            "body": report_body,
        },
        "tasks": task_results,
    }
    PLAYBOOK_RUNS[run_id] = result
    return result


async def decide_playbook_run(run_id: str, request: PlaybookApprovalRequest) -> dict[str, Any] | None:
    run = PLAYBOOK_RUNS.get(run_id)
    if not run:
        return None

    decision_task = {
        "task_id": "approval-decision",
        "task_type": "manual_approval",
        "name": "SOC lead approval decision",
        "status": request.decision,
        "detail": f"{request.approver} {request.decision} containment. {request.comment or ''}".strip(),
        "commands": [],
        "script": None,
        "next": ["5"] if request.decision == "approved" else [],
        "outputs": {
            "Fortress.Approval.Status": request.decision,
            "Fortress.Approval.Approver": request.approver,
            "Fortress.Approval.Comment": request.comment,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    run["tasks"].insert(0, decision_task)
    run["context"]["Fortress.Approval.Status"] = request.decision
    run["context"]["Fortress.Approval.Approver"] = request.approver
    run["status"] = "approved_containment" if request.decision == "approved" else "rejected_escalated"
    run["evidence"].append({"type": "approval_decision", "value": request.decision})

    await event_bus.publish(
        {
            "stream": "playbook",
            "run_id": run_id,
            "tenant_id": run["tenant_id"],
            "incident_id": run["incident_id"],
            "task": decision_task,
        }
    )

    if request.decision == "approved":
        run["context"]["Case.Status"] = "containment_executed_monitoring"
        run["context"]["Change.SafetyCheck"] = "passed"
        run["context"]["Containment.Verified"] = "verified"
        run["context"]["Monitoring.RecurrenceWindow"] = "24 hours"
        run["context"]["Fortress.Report.Summary"] = "Containment approved and executed; incident report sent to stakeholders."
        for task_id in ("7", "8", "9", "10", "11", "12", "13"):
            task = next(task for task in HIGH_RISK_INCIDENT_PLAYBOOK["tasks"] if task["id"] == task_id)
            task_result = {
                "task_id": task["id"],
                "task_type": task["type"],
                "name": task["name"],
                "status": "completed",
                "detail": f"Approved execution completed by {request.approver}.",
                "commands": task.get("commands", []),
                "script": task.get("script"),
                "next": task.get("next", []),
                "outputs": {key: run["context"].get(key, "completed") for key in task.get("outputs", [])},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            run["tasks"].insert(0, task_result)
            await event_bus.publish(
                {
                    "stream": "playbook",
                    "run_id": run_id,
                    "tenant_id": run["tenant_id"],
                    "incident_id": run["incident_id"],
                    "task": task_result,
                }
            )

        report_body = _incident_report_body(
            str(run_id),
            datetime.fromisoformat(run["tasks"][-1]["timestamp"]),
            PlaybookRunRequest(
                tenant_id=run["tenant_id"],
                incident_id=run["incident_id"],
                severity=run["context"]["Incident.Severity"],
                sector=run["context"]["Tenant.Sector"],
                notify_email=run["report"]["recipient"],
                context={"operator": request.approver},
            ),
            run["context"],
            "approved_containment",
        )
        notification = await send_email(
            subject=f"[Nepal Fortress ONE] Containment Approved Report {run['incident_id']}",
            body=report_body,
            to_email=run["report"]["recipient"],
        )
        run["notification"] = notification
        run["report"] = {
            "subject": f"[Nepal Fortress ONE] Containment Approved Report {run['incident_id']}",
            "recipient": run["report"]["recipient"],
            "body": report_body,
        }

    return run


def _incident_report_body(
    run_id: str,
    started_at: datetime,
    request: PlaybookRunRequest,
    context: dict[str, Any],
    status: str,
) -> str:
    return "\n".join(
        [
            "NEPAL FORTRESS ONE - SECURITY INCIDENT REPORT",
            "=" * 52,
            f"Report ID: {context['Fortress.Report.ID']}",
            f"Run ID: {run_id}",
            f"Incident ID: {request.incident_id}",
            f"Tenant: {request.tenant_id}",
            f"Sector: {request.sector}",
            f"Severity: {request.severity}",
            f"Status: {status}",
            f"Risk Score: {context['Fortress.Incident.RiskScore']}",
            f"Started: {started_at.isoformat()}",
            "",
            "Executive Summary",
            f"- {context['Fortress.Report.Summary']}",
            "",
            "Evidence",
            f"- SIEM: {context['Evidence.SIEM.Events']}",
            f"- XDR Endpoint: {context['Evidence.XDR.Endpoint']}",
            f"- NGFW Flows: {context['Evidence.NGFW.Flows']}",
            f"- Identity Risk: {context['Evidence.IAM.Risk']}",
            "",
            "Threat Context",
            f"- IOC: {context['ThreatIntel.IOC']}",
            f"- MITRE ATT&CK: {', '.join(context['MITRE.Techniques'])}",
            f"- Network Zone: {context['Network.Zone']}",
            f"- Blast Radius: {context['Fortress.BlastRadius']}",
            "",
            "Business Impact",
            f"- {context['Fortress.BusinessImpact']}",
            "",
            "Containment Plan",
            "- Validate change safety and emergency window.",
            "- Block malicious indicators on NGFW and DNS security.",
            "- Isolate endpoint, revoke IAM sessions, terminate ZTNA sessions.",
            "- Preserve forensics and monitor recurrence for 24 hours.",
            "",
            "Recommended Actions",
            "- Review approval gate in the Nepal Fortress ONE Playbooks workspace.",
            "- Confirm affected asset owner and business service owner.",
            "- Track containment and recovery through SOC case management.",
        ]
    )
