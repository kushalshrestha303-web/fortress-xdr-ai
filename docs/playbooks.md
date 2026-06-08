# Interactive SOAR Playbooks

The first implemented playbook is `high-risk-incident-response`, modeled after Cortex XSOAR concepts such as content packs, task types, incident context, integration commands, playbook outputs, and manual approval gates.

## Task Types

- Automation: local code that normalizes, scores, summarizes, and updates incident context.
- Integration: command execution against firewall, EDR, IAM, ticketing, email, and threat intelligence systems.
- Condition: branching based on severity, tenant, asset criticality, and confidence.
- Communication: email, ticket, chat, or stakeholder approval.
- Manual approval: SOC lead or incident commander authorization.
- Remediation: isolation, block, quarantine, disable account, revoke token, or open change request.

## XSOAR-Style Runtime

- Content pack: `NepalFortressIncidentResponse`.
- Inputs: tenant, incident, severity, sector, notification recipient.
- Context keys: `Incident.ID`, `Tenant.ID`, `Fortress.Incident.RiskScore`, `ThreatIntel.IOC`, `Network.Zone`.
- Integration command examples: `threatintel-search`, `asset-get`, `ngfw-security-rule-update`, `ngfw-commit`, `xdr-endpoint-isolate`, `iam-session-revoke`, `email-send`.
- Streaming output: every task emits status, detail, commands, output keys, and timestamp over WebSocket.

## Critical-Sector Safety

For banks, hospitals, government, telecom, and critical infrastructure, high-impact actions require explicit approval. The backend currently marks critical runs as `waiting_for_approval`; the next production step is an approvals API with signed approver identity and immutable audit.
