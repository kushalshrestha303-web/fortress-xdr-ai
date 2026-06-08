from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from models import InvestigationResult, RiskScore, TimelineEvent, WazuhAlert


SUSPICIOUS_TERMS = [
    "powershell",
    "encodedcommand",
    "mimikatz",
    "lsass",
    "credential",
    "webshell",
    "rundll32",
    "certutil",
    "whoami",
    "brute force",
    "failed",
]

HIGH_VALUE_AGENT_TERMS = ["dc", "domain", "sql", "finance", "prod", "server", "manager"]


class InvestigationEngine:
    def investigate(self, alert: WazuhAlert, related: list[WazuhAlert]) -> InvestigationResult:
        alert_type = self._alert_type(alert)
        ordered = self._relevant_events(alert, related or [alert], alert_type)
        ordered = sorted(ordered or [alert], key=lambda item: item.timestamp or "")
        if not any(item.id == alert.id for item in ordered):
            ordered.insert(0, alert)

        triage = self._triage(alert, alert_type)
        evidence = self._extract_evidence(alert, ordered)
        mitre = self._mitre(alert, ordered)
        mitre_intelligence = self._mitre_intelligence(mitre)
        attack_chain = self._attack_chain(ordered)
        timeline = [
            TimelineEvent(
                timestamp=item.timestamp,
                alert_id=item.id,
                agent_name=item.agent_name,
                rule_id=item.rule_id,
                rule_level=item.rule_level,
                summary=item.rule_description or item.full_log or "Wazuh alert",
            )
            for item in ordered
        ]
        risk = self._risk(alert, ordered, alert_type)
        classification, verdict = self._classification(alert, ordered, alert_type, risk)
        reasoning = self._classification_reasoning(alert, ordered, alert_type, classification)
        confidence_label, confidence = self._confidence(alert, ordered, alert_type)
        playbook = self._playbook(alert, ordered, risk)
        containment = playbook["containment"]
        active_response = self._active_response_recommendations(alert, ordered, risk)
        analyst_narrative = self._analyst_narrative(alert, ordered, evidence, risk, verdict, alert_type, classification, reasoning)
        executive_report = self._executive_report(alert, ordered, risk, verdict, playbook)
        analyst_report = self._analyst_report(alert, ordered, mitre_intelligence, evidence, risk, playbook, analyst_narrative, active_response)
        executive_summary = self._executive_summary(executive_report)
        workflow_steps = [
            {"step": "Alert triage", "status": "complete", "summary": triage["summary"]},
            {"step": "Alert type determination", "status": "complete", "summary": f"Classified seed alert as {alert_type} before correlation."},
            {"step": "Evidence extraction", "status": "complete", "summary": f"Extracted {sum(len(v) if isinstance(v, list) else bool(v) for v in evidence.values())} evidence fields."},
            {"step": "MITRE ATT&CK mapping", "status": "complete", "summary": f"Mapped {len(mitre)} MITRE entries from Wazuh rule metadata."},
            {"step": "Attack chain reconstruction", "status": "complete", "summary": f"Built attack progression from {len(attack_chain)} evidence-backed stages."},
            {"step": "Timeline reconstruction", "status": "complete", "summary": f"Built timeline from {len(timeline)} related alerts."},
            {"step": "Related alert correlation", "status": "complete", "summary": "Correlated by agent, user, IPs, hostname, rule groups, and MITRE tactic within the investigation window."},
            {"step": "Risk scoring", "status": "complete", "summary": f"Calculated {risk.score}/100 risk and {risk.priority} priority."},
            {"step": "SOC playbook", "status": "complete", "summary": "Generated containment, eradication, recovery, and hunting actions."},
            {"step": "Active response recommendation", "status": "complete", "summary": f"Generated {len(active_response)} analyst-reviewed active response recommendations."},
            {"step": "Analyst report", "status": "complete", "summary": "Generated technical SOC report."},
            {"step": "Executive summary", "status": "complete", "summary": "Generated business-readable summary."},
        ]
        return InvestigationResult(
            alert_id=alert.id,
            created_at=datetime.now(UTC),
            verdict=verdict,
            classification=classification,
            alert_type=alert_type,
            confidence_label=confidence_label,
            confidence=confidence,
            reasoning=reasoning,
            analyst_narrative=analyst_narrative,
            triage=triage,
            evidence=evidence,
            mitre_mapping=mitre,
            mitre_intelligence=mitre_intelligence,
            attack_chain=attack_chain,
            timeline=timeline,
            related_alerts=ordered,
            risk=risk,
            recommended_containment=containment,
            playbook=playbook,
            active_response_recommendations=active_response,
            executive_report=executive_report,
            analyst_report=analyst_report,
            executive_summary=executive_summary,
            workflow_steps=workflow_steps,
        )

    def _alert_type(self, alert: WazuhAlert) -> str:
        groups = {group.lower() for group in alert.rule_groups}
        text = " ".join([alert.alert_source or "", alert.rule_description or "", alert.decoder_name or "", " ".join(alert.mitre_tactics)]).lower()
        if "suricata" in groups or "ids" in groups or "suricata" in text or "network ids" in text:
            return "Network IDS"
        if "malware" in groups or "malware" in text:
            return "Malware"
        if "rootcheck" in groups:
            return "Discovery"
        if "syscheck" in groups or "persistence" in text:
            return "Persistence"
        if "privilege" in text or "sudo" in text or "root executed" in text:
            return "Privilege Escalation"
        if "authentication" in groups or "pam" in groups or "login" in text or "sshd" in text:
            return "Authentication"
        if "lateral" in text or "remote" in text:
            return "Lateral Movement"
        if "discovery" in text or "netstat" in text or "port" in text:
            return "Discovery"
        return "Unknown"

    def _relevant_events(self, seed: WazuhAlert, related: list[WazuhAlert], alert_type: str) -> list[WazuhAlert]:
        relevant = []
        for item in related:
            item_type = self._alert_type(item)
            if item.id == seed.id or item_type == alert_type:
                relevant.append(item)
                continue
            if alert_type == "Network IDS" and self._shares_network_indicator(seed, item):
                relevant.append(item)
            elif alert_type == "Authentication" and item_type in {"Authentication", "Privilege Escalation"} and self._same_user_or_agent(seed, item):
                relevant.append(item)
            elif alert_type == "Privilege Escalation" and item_type in {"Privilege Escalation", "Authentication"} and self._same_user_or_agent(seed, item):
                relevant.append(item)
            elif alert_type in {"Malware", "Persistence", "Discovery", "Lateral Movement"} and item_type == alert_type and self._same_user_or_agent(seed, item):
                relevant.append(item)
        return relevant

    def _shares_network_indicator(self, seed: WazuhAlert, item: WazuhAlert) -> bool:
        seed_values = {seed.srcip, seed.dstip}
        item_values = {item.srcip, item.dstip}
        return bool({value for value in seed_values if value}.intersection({value for value in item_values if value}))

    def _same_user_or_agent(self, seed: WazuhAlert, item: WazuhAlert) -> bool:
        return bool(seed.agent_name and seed.agent_name == item.agent_name) or bool(seed.user_name and seed.user_name == item.user_name)

    def _triage(self, alert: WazuhAlert, alert_type: str) -> dict[str, Any]:
        severity = "critical" if alert.rule_level >= 12 else "high" if alert.rule_level >= 10 else "medium" if alert.rule_level >= 7 else "low"
        return {
            "alert_type": alert_type,
            "severity": severity,
            "summary": f"Wazuh rule {alert.rule_id or 'unknown'} level {alert.rule_level} on {alert.agent_name or 'unknown agent'}: {alert.rule_description or 'No description'}",
            "requires_immediate_review": alert.rule_level >= 10 or bool(alert.mitre_techniques),
        }

    def _extract_evidence(self, alert: WazuhAlert, related: list[WazuhAlert]) -> dict[str, Any]:
        return {
            "agent_name": alert.agent_name,
            "manager_name": alert.manager_name,
            "rule_id": alert.rule_id,
            "rule_level": alert.rule_level,
            "rule_groups": alert.rule_groups,
            "decoder_name": alert.decoder_name,
            "srcip": alert.srcip,
            "dstip": alert.dstip,
            "user_name": alert.user_name,
            "mitre_tactics": alert.mitre_tactics,
            "mitre_techniques": alert.mitre_techniques,
            "related_rule_ids": sorted({item.rule_id for item in related if item.rule_id}),
            "related_agents": sorted({item.agent_name for item in related if item.agent_name}),
            "related_users": sorted({item.user_name for item in related if item.user_name}),
            "full_log": alert.full_log,
        }

    def _mitre(self, alert: WazuhAlert, related: list[WazuhAlert]) -> list[dict[str, Any]]:
        mapped: dict[str, dict[str, Any]] = {}
        for item in related:
            tactics = item.mitre_tactics
            techniques = item.mitre_techniques or []
            for technique in techniques:
                key = technique
                mapped[key] = {
                    "tactic": ", ".join(tactics) if tactics else "Mapped by Wazuh rule metadata",
                    "technique": technique,
                    "source_rule_id": item.rule_id,
                    "evidence": item.rule_description or item.full_log,
                }
        return list(mapped.values())

    def _infer_techniques(self, item: WazuhAlert) -> list[str]:
        text = " ".join([item.rule_description or "", item.full_log or "", " ".join(item.rule_groups)]).lower()
        inferred = []
        if "powershell" in text:
            inferred.append("T1059.001 PowerShell")
        if "brute" in text or "failed" in text or "authentication" in text:
            inferred.append("T1110 Brute Force")
        if "syscheck" in text or "file integrity" in text:
            inferred.append("T1565.001 Stored Data Manipulation")
        if "rootcheck" in text or "rootkit" in text:
            inferred.append("T1014 Rootkit")
        if "malware" in text:
            inferred.append("T1204 User Execution")
        return inferred

    def _risk(self, alert: WazuhAlert, related: list[WazuhAlert], alert_type: str) -> RiskScore:
        score = min(45, alert.rule_level * 4)
        factors = [f"Rule level {alert.rule_level} contributes base severity."]
        all_text = " ".join([item.rule_description or "" for item in related] + [item.full_log or "" for item in related]).lower()
        groups = {group.lower() for item in related for group in item.rule_groups}

        if any(item.mitre_techniques for item in related):
            score += 12
            factors.append("MITRE technique metadata present in Wazuh rule.")
        for group, points in [("malware", 12), ("rootcheck", 8), ("syscheck", 7), ("authentication", 9)]:
            if any(group in value for value in groups):
                score += points
                factors.append(f"Wazuh group `{group}` increases risk.")
        if "powershell" in all_text or "encodedcommand" in all_text:
            score += 12
            factors.append("Suspicious PowerShell evidence found.")
        if "failed" in all_text or "brute" in all_text:
            score += 10
            factors.append("Failed login or brute force language found.")
        if any(value for item in related for value in [item.srcip, item.dstip]):
            score += 5
            factors.append("Network indicator fields present for scoping.")
        if alert_type == "Network IDS":
            score += 10
            factors.append("Seed alert is a network IDS event and requires network validation.")
            if alert.suricata_category:
                factors.append(f"Suricata category: {alert.suricata_category}.")
            if alert.suricata_signature:
                factors.append(f"Suricata signature: {alert.suricata_signature}.")
        if len(related) >= 5:
            score += 10
            factors.append(f"{len(related)} correlated alerts indicate repeated or chained activity.")
        agent_name = (alert.agent_name or "").lower()
        if any(term in agent_name for term in HIGH_VALUE_AGENT_TERMS):
            score += 10
            factors.append("Endpoint name suggests higher asset criticality.")
        if any(term in all_text for term in SUSPICIOUS_TERMS):
            score += 8
            factors.append("Suspicious command or threat behavior terms found in evidence.")

        score = min(100, score)
        priority = "P1" if score >= 85 else "P2" if score >= 70 else "P3" if score >= 45 else "P4"
        return RiskScore(score=score, priority=priority, factors=factors)

    def _classification(self, alert: WazuhAlert, related: list[WazuhAlert], alert_type: str, risk: RiskScore) -> tuple[str, str]:
        if alert_type == "Network IDS":
            if alert.rule_level >= 10 or any(self._alert_type(item) in {"Malware", "Lateral Movement"} for item in related if item.id != alert.id):
                return "Malicious", "Requires Analyst Review"
            if alert.rule_level >= 5 or alert.srcip or alert.dstip or alert.suricata_signature:
                return "Suspicious", "Informational Network Alert"
            return "Informational", "Informational Network Alert"
        if risk.score >= 85:
            return "Malicious", "Critical Incident"
        if risk.score >= 70:
            return "Suspicious", "Confirmed Incident"
        if risk.score >= 45:
            return "Suspicious", "Requires Analyst Review"
        if alert_type == "Authentication" or alert_type == "Privilege Escalation":
            return "Benign", "Benign Administrative Activity"
        return "Informational", "Requires Analyst Review"

    def _confidence(self, alert: WazuhAlert, related: list[WazuhAlert], alert_type: str) -> tuple[str, int]:
        evidence_points = 0
        evidence_points += 1 if alert.rule_id else 0
        evidence_points += 1 if alert.rule_description else 0
        evidence_points += 1 if alert.rule_groups else 0
        evidence_points += 1 if alert_type != "Unknown" else 0
        evidence_points += 1 if len(related) > 1 else 0
        if alert_type == "Network IDS":
            evidence_points += 1 if alert.srcip or alert.dstip else 0
            evidence_points += 1 if alert.suricata_signature else 0
        if evidence_points >= 6:
            return "High", 88
        if evidence_points >= 4:
            return "Medium", 68
        return "Low", 42

    def _classification_reasoning(self, alert: WazuhAlert, related: list[WazuhAlert], alert_type: str, classification: str) -> dict[str, list[str]]:
        supporting = [
            f"Seed alert type determined as {alert_type}.",
            f"Wazuh rule {alert.rule_id or 'unknown'} level {alert.rule_level}: {alert.rule_description or 'No description'}.",
        ]
        missing = []
        if alert_type == "Network IDS":
            if alert.suricata_signature:
                supporting.append(f"Suricata signature: {alert.suricata_signature}.")
            if alert.suricata_category:
                supporting.append(f"Suricata category: {alert.suricata_category}.")
            if alert.srcip or alert.dstip:
                supporting.append(f"Network indicators available: src={alert.srcip or 'unknown'}, dst={alert.dstip or 'unknown'}.")
            if not any(item.id != alert.id for item in related):
                missing.append("No additional relevant network IDS alerts were correlated in the investigation window.")
            missing.extend([
                "No packet payload or PCAP validation is available in the Wazuh alert.",
                "No evidence currently proves the traffic was expected administrative behavior.",
            ])
        else:
            if len(related) <= 1:
                missing.append("No additional same-type events were correlated in the investigation window.")
        chosen = [
            f"Classification `{classification}` was chosen using seed alert type, Wazuh rule level, available indicators, and same-type correlation only.",
        ]
        return {"why_chosen": chosen, "supporting_evidence": supporting, "missing_evidence": missing}

    def _playbook(self, alert: WazuhAlert, related: list[WazuhAlert], risk: RiskScore) -> dict[str, list[str]]:
        indicators = sorted({value for item in related for value in [item.srcip, item.dstip] if value})
        containment = [
            "Validate the Wazuh alert against raw log, decoder output, and endpoint context.",
            f"Scope related alerts for agent `{alert.agent_name or 'unknown'}` within the +/- 30 minute window.",
        ]
        if risk.score >= 80:
            containment.append(f"Recommend isolating endpoint `{alert.agent_name or 'unknown'}` after analyst validation.")
        if alert.user_name:
            containment.append(f"Review account `{alert.user_name}` for unauthorized activity.")
        if indicators:
            containment.append(f"Block or monitor suspicious IP indicators after validation: {', '.join(indicators)}.")
        containment.append("Preserve full logs, Wazuh alert JSON, endpoint telemetry, and relevant packet/proxy evidence.")

        eradication = [
            "Remove confirmed malicious files, persistence entries, unauthorized accounts, or scheduled tasks if found in evidence.",
            "Revert unauthorized configuration changes identified during host review.",
        ]
        recovery = [
            "Restore normal host access only after suspicious activity is validated as contained or benign.",
            "Reset credentials for affected users if account compromise is confirmed or strongly suspected.",
        ]
        hunting = [
            "Search Wazuh for the same rule id, agent, user, source IP, destination IP, and MITRE tactic.",
            "Review nearby authentication, privilege escalation, rootcheck, syscheck, malware, and network alerts.",
        ]
        return {
            "containment": containment,
            "eradication": eradication,
            "recovery": recovery,
            "threat_hunting": hunting,
        }

    def _active_response_recommendations(self, alert: WazuhAlert, related: list[WazuhAlert], risk: RiskScore) -> list[str]:
        recommendations = [
            "Do not execute automatically. Require analyst approval before triggering Wazuh active response.",
        ]
        indicators = sorted({value for item in related for value in [item.srcip, item.dstip] if value})
        if indicators:
            recommendations.append(f"Recommend Wazuh active response to block validated IP indicators: {', '.join(indicators)}.")
        if alert.user_name:
            recommendations.append(f"Recommend disabling or forcing password reset for `{alert.user_name}` only if account compromise is confirmed.")
        if risk.score >= 80:
            recommendations.append(f"Recommend endpoint isolation workflow for `{alert.agent_name or 'unknown'}` after business owner approval.")
        recommendations.append("Recommend opening a case/ticket and attaching the Wazuh alert JSON, timeline, and analyst notes.")
        return recommendations

    def _attack_chain(self, related: list[WazuhAlert]) -> list[dict[str, Any]]:
        chain = []
        for index, item in enumerate(sorted(related, key=lambda alert: alert.timestamp or ""), start=1):
            text = " ".join([item.rule_description or "", item.full_log or "", " ".join(item.rule_groups), " ".join(item.mitre_tactics)]).lower()
            stage = self._stage_from_text(text)
            chain.append({
                "event": index,
                "stage": stage,
                "timestamp": item.timestamp,
                "alert_id": item.id,
                "agent_name": item.agent_name,
                "rule_id": item.rule_id,
                "rule_level": item.rule_level,
                "summary": item.rule_description or item.full_log or "Wazuh alert",
                "mitre_tactics": item.mitre_tactics,
            })
        return chain

    def _stage_from_text(self, text: str) -> str:
        if "authentication" in text or "login" in text or "pam" in text or "failed" in text:
            return "Authentication"
        if "sudo" in text or "privilege" in text or "root" in text:
            return "Privilege Escalation"
        if "persistence" in text or "systemd" in text or "cron" in text or "service" in text:
            return "Persistence"
        if "syscheck" in text or "file integrity" in text:
            return "File Integrity"
        if "rootcheck" in text:
            return "Rootcheck"
        if "suricata" in text or "network" in text or "connection" in text or "port" in text:
            return "Network Activity"
        if "malware" in text:
            return "Malware"
        if "discovery" in text or "netstat" in text:
            return "Discovery"
        if "exfil" in text or "upload" in text or "transfer" in text:
            return "Exfiltration"
        return "Observed Activity"

    def _mitre_intelligence(self, mitre: list[dict[str, Any]]) -> list[dict[str, Any]]:
        intelligence = []
        for item in mitre:
            technique = item.get("technique") or ""
            parts = technique.split(" ", 1)
            technique_id = parts[0] if parts and parts[0].startswith("T") else technique
            technique_name = parts[1] if len(parts) > 1 else technique
            evidence = item.get("evidence") or "Wazuh alert contained MITRE technique metadata."
            intelligence.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": item.get("tactic"),
                "why_mapped": f"Wazuh rule {item.get('source_rule_id') or 'unknown'} included this MITRE mapping.",
                "analyst_explanation": f"The mapping is supported by Wazuh rule metadata and alert evidence: {evidence}",
                "source_rule_id": item.get("source_rule_id"),
            })
        return intelligence

    def _analyst_narrative(self, alert: WazuhAlert, related: list[WazuhAlert], evidence: dict[str, Any], risk: RiskScore, verdict: str, alert_type: str, classification: str, reasoning: dict[str, list[str]]) -> str:
        if alert_type == "Network IDS":
            lines = [
                f"Alert {alert.rule_id or alert.id} is a Network IDS alert generated by Wazuh/Suricata on host {alert.agent_name or 'unknown'}.",
                f"Description: {alert.rule_description or 'No description available'}.",
                "",
                "Network evidence:",
                f"- Source IP: {alert.srcip or 'not present'}",
                f"- Destination IP: {alert.dstip or 'not present'}",
                f"- Signature: {alert.suricata_signature or 'not present'}",
                f"- Category: {alert.suricata_category or 'not present'}",
                f"- IDS severity: {alert.suricata_severity or 'not present'}",
                f"- Protocol: {alert.suricata_protocol or 'not present'}",
                "",
                f"Correlation analysis retained {len(related)} relevant network event(s). Authentication and sudo/login events were not used to downgrade this network IDS classification.",
                "",
                "Reasoning:",
                *[f"- {item}" for item in reasoning["why_chosen"]],
                *[f"- Evidence: {item}" for item in reasoning["supporting_evidence"]],
                *[f"- Missing: {item}" for item in reasoning["missing_evidence"]],
                "",
                "SOC recommendations:",
                "- Investigate the source IP.",
                "- Review additional Suricata alerts for the same source or destination.",
                "- Validate whether the traffic is expected for this host.",
                "- Hunt for related indicators across Wazuh alerts.",
                "",
                "Final Classification:",
                f"{classification} - {verdict}",
            ]
            return "\n".join(lines)

        descriptions = [item.rule_description or "" for item in related]
        text = " ".join(descriptions + [item.full_log or "" for item in related]).lower()
        count_login_open = sum("login session opened" in value.lower() or "successful login" in value.lower() for value in descriptions)
        count_login_close = sum("login session closed" in value.lower() for value in descriptions)
        count_sudo = sum("sudo" in value.lower() or "root" in value.lower() for value in descriptions)
        count_failed = sum("failed" in value.lower() or "failure" in value.lower() or "brute" in value.lower() for value in descriptions)
        count_malware = sum(any(group.lower() == "malware" for group in item.rule_groups) or "malware" in (item.rule_description or "").lower() for item in related)
        count_powershell = sum("powershell" in ((item.full_log or "") + " " + (item.rule_description or "")).lower() for item in related)
        network_indicators = sorted({value for item in related for value in [item.srcip, item.dstip] if value})

        lines = [
            f"Alert {alert.rule_id or alert.id} indicates {alert.rule_description or 'a Wazuh alert'} on host {alert.agent_name or 'unknown'}.",
            "",
            "Correlation analysis identified:",
            f"- {count_login_open} successful login/session-open event(s).",
            f"- {count_sudo} sudo or privilege-related event(s).",
            f"- {count_login_close} session-close event(s).",
            f"- {len(related)} related alert(s) in the investigation window.",
            "",
            f"{'Failed login or brute-force indicators were detected.' if count_failed else 'No brute-force attempts were detected in the correlated alerts.'}",
            f"{'PowerShell activity was detected in the correlated alerts.' if count_powershell else 'No suspicious PowerShell activity was detected.'}",
            f"{'Malware-related Wazuh evidence was detected.' if count_malware else 'No malware indicators were detected in Wazuh rule groups or descriptions.'}",
            f"{'Network indicators were present: ' + ', '.join(network_indicators) + '.' if network_indicators else 'No suspicious outbound network connections were detected from available srcip/dstip fields.'}",
            "",
        ]
        if risk.score < 45:
            lines.append("The observed behavior appears consistent with benign or routine administrative activity based on available Wazuh evidence.")
        elif risk.score < 70:
            lines.append("The observed behavior is suspicious enough to warrant analyst review, but the available evidence does not confirm compromise.")
        else:
            lines.append("The observed behavior may represent malicious or unauthorized activity and should be prioritized for containment review.")
        lines.extend(["", "Final Classification:", verdict])
        return "\n".join(lines)

    def _executive_report(self, alert: WazuhAlert, related: list[WazuhAlert], risk: RiskScore, verdict: str, playbook: dict[str, list[str]]) -> dict[str, Any]:
        affected_assets = sorted({item.agent_name for item in related if item.agent_name}) or [alert.agent_name or "unknown"]
        severity = "Critical" if risk.score >= 85 else "High" if risk.score >= 70 else "Medium" if risk.score >= 45 else "Low"
        return {
            "executive_summary": f"FORTRESS XDR AI investigated Wazuh rule {alert.rule_id or 'unknown'} on {alert.agent_name or 'unknown'} and classified it as {verdict}.",
            "business_impact": "No business impact is confirmed from the available alert evidence." if risk.score < 45 else "Potential operational or account risk exists and requires analyst validation.",
            "affected_assets": affected_assets,
            "severity": severity,
            "recommended_actions": playbook["containment"][:3],
        }

    def _verdict(self, score: int) -> str:
        if score >= 85:
            return "Critical Incident"
        if score >= 70:
            return "Confirmed Incident"
        if score >= 45:
            return "Suspicious"
        return "Benign Administrative Activity"

    def _analyst_report(self, alert: WazuhAlert, related: list[WazuhAlert], mitre_intelligence: list[dict[str, Any]], evidence: dict[str, Any], risk: RiskScore, playbook: dict[str, list[str]], analyst_narrative: str, active_response: list[str]) -> str:
        mitre_lines = "\n".join(f"- {item['technique_id']} {item['technique_name']}: {item['why_mapped']}" for item in mitre_intelligence) or "- No MITRE mapping present in Wazuh metadata."
        timeline_lines = "\n".join(f"- {item.timestamp} | {item.agent_name} | rule {item.rule_id} level {item.rule_level} | {item.rule_description}" for item in related)
        playbook_lines = "\n".join(
            f"### {section.replace('_', ' ').title()}\n" + "\n".join(f"- {action}" for action in actions)
            for section, actions in playbook.items()
        )
        return f"""# FORTRESS XDR AI Analyst Report

## AI Analyst Narrative
{analyst_narrative}

## Alert
- Alert ID: {alert.id}
- Agent: {alert.agent_name}
- Manager: {alert.manager_name}
- Rule: {alert.rule_id}
- Level: {alert.rule_level}
- Description: {alert.rule_description}
- Decoder: {alert.decoder_name}

## Evidence
- Source IP: {evidence.get('srcip')}
- Destination IP: {evidence.get('dstip')}
- User: {evidence.get('user_name')}
- Rule groups: {', '.join(evidence.get('rule_groups') or [])}

## MITRE ATT&CK Intelligence
{mitre_lines}

## Correlated Timeline
{timeline_lines}

## Risk
- Score: {risk.score}/100
- Priority: {risk.priority}
{chr(10).join(f"- {factor}" for factor in risk.factors)}

## SOC Investigation Playbook
{playbook_lines}

## Wazuh Active Response Recommendations
{chr(10).join(f"- {action}" for action in active_response)}
"""

    def _executive_summary(self, report: dict[str, Any]) -> str:
        return f"""# FORTRESS XDR AI Executive Summary

## Executive Summary
{report['executive_summary']}

## Business Impact
{report['business_impact']}

## Affected Assets
{chr(10).join(f"- {asset}" for asset in report['affected_assets'])}

## Severity
{report['severity']}

## Recommended Actions
{chr(10).join(f"- {action}" for action in report['recommended_actions'])}
"""
