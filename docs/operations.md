# SOC Operations

## Incident Lifecycle

1. Ingest telemetry from XDR, NGFW, cloud, IAM, DNS, email, and threat feeds.
2. Normalize to tenant-aware event schema.
3. Enrich with assets, identity, vulnerability, geo, IOC, and MITRE ATT&CK context.
4. Correlate into incidents with risk scoring.
5. Run interactive playbooks with human approval gates.
6. Contain through EDR isolation, firewall block, IAM disablement, DNS sinkhole, or ticket escalation.
7. Preserve evidence and generate timeline, summary, and lessons learned.

## NGFW Operations

The dedicated NGFW logs view tracks:

- Deep packet inspection evidence such as SNI, HTTP host, file type, payload hash, and user agent.
- Application-level filtering decisions by application, policy, rule, source, destination, and sector.
- Intrusion prevention metrics including signatures, CVEs, severity, and block state.
- Sector visibility across hospitals, banks, government, telecom, critical infrastructure, and enterprise tenants.

## Email Notification

Playbook runs default to notifying `kushalshrestha993@gmail.com`. Configure SMTP in `services/api/.env`:

```text
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=soc@example.com
SMTP_PASSWORD=change-me
SMTP_FROM=soc@example.com
SECURITY_NOTIFICATION_TO=kushalshrestha993@gmail.com
```

Without SMTP settings, the platform records that email delivery is not configured and still returns the intended recipient.
