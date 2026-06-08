# Enterprise Architecture

```mermaid
flowchart LR
  A["Hospitals, Banks, Government, Telecom, Enterprise"] --> B["Cisco/Branch/Core Network Zones"]
  B --> C["Real NGFW Sensors: Suricata, Zeek, Firewall APIs"]
  B --> D["Fortress Shield XDR Agents"]
  C --> E["Kafka/Redpanda Event Backbone"]
  D --> E
  E --> F["FastAPI Ingestion Services"]
  E --> G["Fortress AI Brain"]
  F --> H["ClickHouse Hot Analytics"]
  F --> I["OpenSearch SIEM Index"]
  F --> J["PostgreSQL Control Plane"]
  G --> K["Risk Scoring and Correlation"]
  K --> L["SOC Cloud and SOAR"]
  L --> M["Command Center UI"]
  L --> N["Email, Ticketing, Firewall, EDR, IAM Actions"]
```

## Network Architecture

- Bank sector: internet edge NGFW pair, DMZ, core banking segment, payment switch segment, SOC tap/SPAN, privileged admin network, SWIFT/HSM enclave.
- Hospital sector: clinical network, PACS/RIS, EHR, medical IoT VLANs, guest isolation, emergency services segment.
- Government sector: citizen services DMZ, ministry WAN, identity federation, classified enclaves, national CERT monitoring.
- Telecom sector: OSS/BSS, subscriber core, signaling security, lawful intercept separation, NOC/SOC shared telemetry.

Cisco-style design principles:

- Hierarchical campus core/distribution/access segmentation.
- VRF-lite or SD-WAN segmentation between sectors.
- NGFW inspection between trust zones, not only at the internet edge.
- NetFlow/IPFIX, SPAN/TAP, DNS, DHCP, VPN, IAM, and EDR telemetry into the event backbone.
- Microsegmentation enforced through Kubernetes NetworkPolicy, service mesh authorization, and firewall policy.

## Data Plane

- Kafka/Redpanda topics: `endpoint.telemetry`, `ngfw.logs`, `ids.alerts`, `dns.events`, `identity.events`, `cloud.audit`, `incidents`, `playbook.runs`.
- ClickHouse: high-volume analytics and packet/security metrics.
- OpenSearch: SIEM search, detection content, dashboards.
- PostgreSQL: tenants, policies, users, cases, playbooks, integrations.
- Redis: rate limits, live session state, short-lived correlation windows.

## Control Plane

- API gateway with OIDC, MFA/passkeys, tenant routing, rate limiting, and request signing.
- Istio mTLS between services.
- Vault-managed secrets and short-lived workload credentials.
- ArgoCD GitOps deployment with signed manifests.

