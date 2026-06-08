import asyncio

from app.models.events import NgfwLog, PlaybookApprovalRequest, PlaybookRunRequest, TelemetryEvent
from app.services.risk import score_event, score_ngfw_log
from app.services.playbook_engine import HIGH_RISK_INCIDENT_PLAYBOOK, decide_playbook_run, run_high_risk_playbook


def test_event_risk_scores_sector_and_mitre() -> None:
    event = TelemetryEvent(
        tenant_id="gov-cert",
        sector="government",
        source="xdr-agent",
        event_type="credential_access",
        severity="high",
        mitre_techniques=["T1003", "T1055"],
    )
    assert score_event(event) >= 80


def test_ngfw_critical_ips_scores_high() -> None:
    log = NgfwLog(
        tenant_id="bank",
        sector="bank",
        sensor_id="fw-01",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.10",
        protocol="TLS",
        application="unknown-tunnel",
        action="blocked",
        ips={"signature": "C2 traffic", "severity": "critical", "cve": "CVE-2026-0001"},
    )
    assert score_ngfw_log(log) == 100


def test_playbook_uses_xsoar_style_task_graph() -> None:
    task_types = {task["type"] for task in HIGH_RISK_INCIDENT_PLAYBOOK["tasks"]}
    assert {"automation", "integration", "condition", "manual_approval", "communication"} <= task_types
    assert HIGH_RISK_INCIDENT_PLAYBOOK["content_pack"] == "NepalFortressIncidentResponse"


def test_playbook_approval_advances_run() -> None:
    async def scenario() -> dict[str, object] | None:
        run = await run_high_risk_playbook(
            PlaybookRunRequest(tenant_id="bank", incident_id="INC-APPROVE", severity="critical", sector="bank")
        )
        return await decide_playbook_run(
            run["run_id"],
            PlaybookApprovalRequest(approver="soc-lead@example.com", decision="approved", comment="Validated containment."),
        )

    decided = asyncio.run(scenario())
    assert decided is not None
    assert decided["status"] == "approved_containment"
