# Security Design

## Zero Trust

- Every request is authenticated, authorized, logged, and tenant-scoped.
- RBAC handles job function; ABAC handles tenant, sector, sensitivity, asset criticality, and approval state.
- Service-to-service traffic uses mTLS through Istio.
- Playbook remediation requires approval gates for destructive or availability-impacting actions.

## Supply Chain

- SAST: Semgrep, CodeQL.
- Dependency scanning: OSV, Trivy, npm audit, pip-audit, govulncheck.
- Container scanning: Trivy and Grype.
- SBOM: Syft CycloneDX.
- Signing: Cosign for containers and attestations.
- Policy: Kyverno/Gatekeeper for Kubernetes admission.

## Threat Model

- Stolen SOC analyst credentials: require MFA/passkeys, device posture, just-in-time elevation, impossible-travel detection.
- Compromised endpoint agent: mTLS identity, least privilege, signed policy updates, server-side validation.
- Malicious insider: dual approval for containment at critical sectors, tamper-resistant audit logs, immutable evidence.
- Ransomware lateral movement: microsegmentation, EDR isolation, anomalous SMB/RDP detection, privileged account throttling.
- Supply-chain compromise: signed builds, SBOMs, provenance, dependency pinning, admission control.

## Abuse Cases

- Analyst tries to run isolation against an entire hospital subnet without approval.
- Tenant operator attempts to query another tenant's incidents.
- Integration tries to exfiltrate secrets from Vault.
- Fake NGFW sensor sends forged logs without a valid device certificate.
- Malware sandbox sample attempts to escape to the management network.

