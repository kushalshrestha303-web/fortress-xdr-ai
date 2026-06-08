# 🛡️ Fortress XDR AI - Enterprise Security Operations Center

**A production-grade AI-powered Extended Detection and Response (XDR) platform** for real-time security threat detection, investigation, and automated response.

> This is a **real enterprise SOC platform** designed to connect with actual security infrastructure and process real cybersecurity telemetry.

---

## 🎯 Mission

Fortress XDR AI is a modern, scalable SOC platform that ingests, correlates, analyzes, hunts, and investigates **real security events** from multiple enterprise data sources using advanced AI and machine learning.

---

## 📊 Core Capabilities

### 🔍 **Real-Time Security Monitoring**
- Live event ingestion from Wazuh, Sysmon, Windows Logs, Linux Audit, Suricata IDS/IPS
- Real-time alert processing and correlation
- Automated threat scoring and severity assessment
- Interactive SOC dashboard with streaming alerts

### 🤖 **AI-Powered Threat Detection**
- **Brute Force Attacks** - Pattern recognition on failed authentications
- **Credential Stuffing & Password Spraying** - Suspicious auth patterns
- **Malware & Ransomware** - Detection of malicious executables and indicators
- **Persistence Techniques** - Registry mods, scheduled tasks, startup locations
- **Privilege Escalation** - UAC bypass, token impersonation, sudo abuse
- **PowerShell Abuse** - Script execution, encoded commands, C2 activity
- **Command Injection** - Shell metacharacter detection, process spawning
- **Reverse Shells** - Network connection patterns to suspicious IPs
- **Web Attacks** - SQLi, XSS, directory traversal patterns
- **Lateral Movement** - Pass-the-hash, PsExec, WinRM abuse
- **Living Off The Land** - Legitimate tool misuse (LOLBins)
- **Data Exfiltration** - Suspicious outbound connections, DNS tunneling
- **Reconnaissance** - Port scanning, enumeration activity

### 🎯 **Threat Hunting Module**
- Pre-built hunt templates for common attack patterns
- Support for multiple query languages:
  - KQL (Kibana Query Language)
  - Sigma Rules
  - YARA Rules
  - Wazuh Rules
  - OpenSearch Queries
  - Natural Language queries
- Custom threat hunt creation and execution
- Hunt history and results tracking

### 📈 **MITRE ATT&CK Mapping**
- Automatic technique/tactic mapping for all detections
- Interactive ATT&CK Navigator visualization
- Attack chain visualization (Initial Access → Exfiltration)
- Technique coverage analysis

### 🔗 **XDR Correlation Engine**
- Multi-source event correlation
- Automatic attack story building
- Context-aware risk scoring
- Behavioral analytics
- Anomaly detection

### 🧠 **AI SOC Analyst**
- **Alert Explanation** - Natural language explanations of security events
- **Attack Chain Analysis** - Automatic reconstruction of attack flow
- **MITRE Mapping** - Technique/tactic identification and explanation
- **CVE Analysis** - Vulnerability context and remediation guidance
- **Incident Reports** - Comprehensive SOC analyst reports
- **Executive Reports** - Executive summaries with risk metrics
- **Remediation Recommendations** - Actionable response steps

### 🔍 **AI Incident Investigator**
- Automatic incident investigation workflow
- Source/destination/user/process identification
- Parent process analysis
- MITRE technique mapping
- Attack severity scoring
- Automated incident timeline generation

### 📊 **Advanced Reporting**
- **SOC Analyst Reports** - Detailed technical investigation
- **Executive Reports** - Risk overview and metrics
- **Compliance Reports** - ISO 27001, NIST CSF, PCI DSS, SOC 2
- **Export Formats** - PDF, DOCX, CSV, JSON
- **Custom Report Builder** - Create tailored reports

### 🚨 **Automated Response**
- Wazuh Active Response integration
- IP blocking/allowlisting
- Process termination
- User account disabling
- Host isolation
- AI-recommended actions before execution

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js)                       │
│              React Dashboard + TypeScript + TailwindCSS          │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                         API Gateway (Nginx)                      │
│                    JWT Auth + Rate Limiting                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    Backend (FastAPI + Python)                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Core Services:                                           │   │
│  │ • Alert Processing  • Event Correlation                  │   │
│  │ • Threat Hunting    • Incident Investigation             │   │
│  │ • Report Generation • Response Management                │   │
│  └──────────────────────────────────────────────────────────┘   │
└──┬──────────────┬──────────────────┬──────────────┬─────────────┘
   │              │                  │              │
   ▼              ▼                  ▼              ▼
┌────────┐  ┌──────────────┐  ┌────────────┐  ┌─────────┐
│Database│  │   Search     │  │  AI Engine │  │ Cache   │
│(Postgre)  │(OpenSearch)  │  │  (OpenAI)  │  │(Redis)  │
└────────┘  └──────────────┘  └────────────┘  └─────────┘
   │              │                  │
   └──────────────┼──────────────────┘
                  │
        ┌─────────▼─────────┐
        │ Data Connectors   │
        ├───────────────────┤
        │ • Wazuh API       │
        │ • Sysmon          │
        │ • Windows Logs    │
        │ • Suricata IDS    │
        │ • Linux Audit     │
        │ • Threat Intel    │
        └───────────────────┘
```

---

## 📚 Data Sources

### Wazuh Integration
- Direct Wazuh API connectivity
- Alert ingestion from Wazuh Indexer/OpenSearch
- Agent status monitoring
- Vulnerability scanning results
- File Integrity Monitoring (FIM) events
- Active Response integration

### Windows Security Events
- **Sysmon Events**: Process creation, network connections, DLL loading, registry modifications
- **Event Logs**: Security logs, PowerShell logs, Windows Defender logs, System logs, Application logs

### Linux Security Events
- **Linux Audit (auditd)**: System calls, process execution, file access
- **Auth Logs**: Login attempts, sudo execution
- **SSH Logs**: Authentication attempts, connection tracking
- **Syslog**: System-wide logging

### Network Security Events
- **Suricata IDS/IPS**: Intrusion detection signatures, protocol analysis
- **Zeek Network Monitor**: Network flow analysis, protocol metadata
- **DNS Logs**: Domain queries, suspicious patterns
- **Firewall Logs**: Connection tracking, rule hits

### Threat Intelligence
- **VirusTotal API**: File hashing, malware detection
- **MITRE ATT&CK Framework**: Technique mapping and context
- **Custom TI Feeds**: Custom IOC ingestion

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 18+
- Wazuh (optional, for full integration)
- OpenAI API Key (for AI features)

### Installation

```bash
# Clone repository
git clone https://github.com/kushalshrestha303-web/fortress-xdr-ai.git
cd fortress-xdr-ai

# Create environment files
cp .env.example .env
# Edit .env with your configuration

# Start with Docker Compose
docker-compose up -d

# Run migrations
docker-compose exec backend python -m alembic upgrade head

# Create admin user
docker-compose exec backend python -m scripts.create_admin
```

### Access the Platform
- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Admin Panel**: http://localhost:3000/admin

---

## 📁 Project Structure

```
fortress-xdr-ai/
├── frontend/                      # Next.js Dashboard
│   ├── app/                      # Next.js app directory
│   ├── components/               # React components
│   ├── lib/                      # Utilities & helpers
│   ├── styles/                   # TailwindCSS styles
│   └── package.json
│
├── backend/                      # FastAPI Backend
│   ├── app/
│   │   ├── api/                 # API routes
│   │   ├── models/              # Pydantic models
│   │   ├── services/            # Business logic
│   │   ├── schemas/             # Database schemas
│   │   ├── connectors/          # Data source connectors
│   │   ├── ai/                  # AI/ML modules
│   │   └── utils/               # Utilities
│   ├── alembic/                 # Database migrations
│   ├── tests/                   # Unit & integration tests
│   └── requirements.txt
│
├── database/                     # PostgreSQL
│   ├── schema.sql               # Database schema
│   └── migrations/
│
├── docker/                       # Docker configurations
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
│
├── connectors/                   # Data source connectors
│   ├── wazuh/
│   ├── sysmon/
│   ├── suricata/
│   └── windows/
│
├── rules/                        # Detection rules
│   ├── sigma_rules/
│   ├── yara_rules/
│   └── wazuh_rules/
│
├── docs/                         # Documentation
│   ├── architecture.md
│   ├── api-guide.md
│   ├── deployment.md
│   ├── threat-hunting.md
│   └── soc-analyst-guide.md
│
└── scripts/                      # Utilities & scripts
    ├── create_admin.py
    ├── import_rules.py
    └── generate_reports.py
```

---

## 🔑 Key Features

### 1. Real-Time Alert Dashboard
- Live streaming alerts
- Alert filtering and search
- Severity and status tracking
- Quick investigation links
- Alert correlation visualization

### 2. Threat Hunting Console
- Natural language query interface
- Pre-built hunt templates
- Multi-query type support (KQL, Sigma, YARA, etc.)
- Hunt result visualization
- Search history

### 3. Incident Investigation
- Automatic incident timeline generation
- Process tree visualization
- Network connection mapping
- User activity tracking
- Impact assessment

### 4. MITRE ATT&CK Visualization
- Interactive ATT&CK Navigator
- Technique heatmap
- Attack chain visualization
- Coverage analysis

### 5. AI-Powered Analysis
- ChatGPT-style conversation interface
- Context-aware threat analysis
- Automatic report generation
- Remediation recommendations
- Attack explanation

### 6. Compliance & Reporting
- Pre-built compliance templates
- Automated report generation
- Multi-format export (PDF, DOCX, CSV)
- Custom report builder
- Audit trails

---

## 🛠️ Technology Stack

**Frontend**
- Next.js 13+ (React framework)
- TypeScript (Type safety)
- TailwindCSS (Styling)
- ShadCN UI (Component library)
- Recharts (Data visualization)
- Socket.io (Real-time updates)

**Backend**
- FastAPI (Python web framework)
- PostgreSQL (Relational database)
- OpenSearch (Log search & analytics)
- Redis (Caching & queuing)
- Celery (Task queue)
- OpenAI API (AI capabilities)

**Infrastructure**
- Docker & Docker Compose
- Nginx (Reverse proxy)
- Linux (Ubuntu 22.04 LTS)
- JWT (Authentication)
- RBAC (Authorization)

---

## 🔐 Security Features

- **JWT Authentication** - Secure token-based auth
- **Role-Based Access Control (RBAC)** - Fine-grained permissions
- **Multi-Factor Authentication (MFA)** - 2FA support
- **Encryption** - TLS/SSL for data in transit, AES-256 for sensitive data at rest
- **Audit Logging** - Complete activity tracking
- **API Rate Limiting** - DDoS protection
- **SQL Injection Prevention** - Parameterized queries
- **CSRF Protection** - Token-based CSRF prevention

---

## 📊 Sample Detection Rules

### Brute Force Attack
```yaml
title: Multiple Failed Login Attempts
severity: high
timeframe: 5m
condition: >
  Failed logins from same source > 10 OR
  Failed logins from same user > 15
actions:
  - alert
  - block_ip (optional)
```

### PowerShell Abuse
```yaml
title: Suspicious PowerShell Execution
severity: critical
detection:
  - Event ID 4688 (Process Creation)
  - CommandLine contains: 'powershell', 'DownloadString', 'IEX'
  - Encoded command detected
mitre:
  - T1086 (PowerShell)
  - T1027 (Obfuscation)
```

### Lateral Movement
```yaml
title: Lateral Movement via PsExec
severity: critical
detection:
  - Network connection to port 445 (SMB)
  - Process: PsExec64.exe OR psexec.exe
  - Service creation on remote host
mitre:
  - T1021.002 (Remote Services: SMB/Windows Admin Shares)
  - T1569.002 (System Services: Service Execution)
```

---

## 🤖 AI Capabilities

### Natural Language Threat Hunting
```
User: "Show suspicious PowerShell activity in the last 24 hours"
AI: [Searches telemetry data for PowerShell processes with suspicious characteristics]
     Returns: 23 events matching criteria with MITRE context
```

### Incident Analysis
```
User: "Analyze this alert [alert_id]"
AI: 
  - Explains what happened
  - Shows attack chain
  - Maps to MITRE framework
  - Recommends response actions
  - Suggests detection improvements
```

### Report Generation
```
User: "Generate incident report for [incident_id]"
AI: Creates comprehensive report with:
  - Executive summary
  - Technical details
  - Timeline
  - IOCs
  - Recommendations
  - Compliance impact
```

---

## 📡 API Documentation

### Alerts API
```
GET    /api/v1/alerts              # List alerts
GET    /api/v1/alerts/{id}         # Get alert details
POST   /api/v1/alerts/search       # Advanced alert search
PATCH  /api/v1/alerts/{id}         # Update alert
DELETE /api/v1/alerts/{id}         # Delete alert
```

### Incidents API
```
GET    /api/v1/incidents           # List incidents
POST   /api/v1/incidents           # Create incident
GET    /api/v1/incidents/{id}      # Get incident details
PATCH  /api/v1/incidents/{id}      # Update incident
POST   /api/v1/incidents/{id}/close # Close incident
```

### Threat Hunting API
```
GET    /api/v1/hunts               # List hunts
POST   /api/v1/hunts               # Create hunt
POST   /api/v1/hunts/{id}/execute  # Execute hunt
GET    /api/v1/hunts/{id}/results  # Get hunt results
```

### AI Analysis API
```
POST   /api/v1/ai/analyze-alert    # Analyze alert with AI
POST   /api/v1/ai/investigate      # AI-powered investigation
POST   /api/v1/ai/generate-report  # AI report generation
POST   /api/v1/ai/chat             # Chat with AI analyst
```

### Reporting API
```
GET    /api/v1/reports             # List reports
POST   /api/v1/reports             # Create report
GET    /api/v1/reports/{id}        # Get report
POST   /api/v1/reports/{id}/export # Export report (PDF/DOCX)
```

---

## 🧪 Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Generate coverage report
pytest --cov=app tests/

# Run frontend tests
cd frontend && npm test
```

---

## 📖 Documentation

- **[Architecture Overview](./docs/architecture.md)** - System design and components
- **[API Guide](./docs/api-guide.md)** - Complete API reference
- **[Deployment Guide](./docs/deployment.md)** - Production deployment steps
- **[Threat Hunting Guide](./docs/threat-hunting.md)** - Hunt templates and examples
- **[SOC Analyst Guide](./docs/soc-analyst-guide.md)** - Platform usage guide
- **[Wazuh Integration](./docs/wazuh-integration.md)** - Wazuh setup and configuration
- **[Sysmon Integration](./docs/sysmon-integration.md)** - Sysmon integration guide

---

## 🔄 Workflow Example

### Alert Detection → Investigation → Response

```
1. EVENT INGESTION
   └─ Wazuh detects 50 failed logins in 5 minutes

2. CORRELATION
   └─ XDR engine correlates with other indicators
   └─ Risk score increases based on patterns

3. AI ANALYSIS
   └─ AI analyzes context and generates alert explanation
   └─ Identifies potential brute force attack
   └─ Maps to MITRE T1110 (Brute Force)

4. INVESTIGATION
   └─ AI generates incident timeline
   └─ Identifies source IP, target user, affected systems
   └─ Retrieves related network logs and process executions

5. RECOMMENDATION
   └─ AI recommends blocking source IP
   └─ Suggests enabling MFA
   └─ Recommends password reset

6. RESPONSE
   └─ SOC analyst reviews recommendation
   └─ Executes block via Wazuh Active Response
   └─ Creates change ticket

7. REPORTING
   └─ AI generates comprehensive incident report
   └─ Export as PDF for stakeholders
```

---

## 🚨 Supported Alert Types

- ✅ Brute Force Attacks (SSH, RDP, SMB)
- ✅ Credential Stuffing & Password Spraying
- ✅ Malware Detection (File hash signatures)
- ✅ Ransomware Indicators (Behavioral patterns)
- ✅ Persistence Mechanisms (Registry, Scheduled Tasks)
- ✅ Privilege Escalation (UAC bypass, Token theft)
- ✅ PowerShell Abuse (Encoded commands, C2)
- ✅ Command Injection (Shell metacharacters)
- ✅ Reverse Shell Activity (Network patterns)
- ✅ Web Application Attacks (SQLi, XSS, path traversal)
- ✅ Lateral Movement (PsExec, Pass-the-Hash, WinRM)
- ✅ Living Off The Land (LOLBins abuse)
- ✅ Data Exfiltration (Suspicious uploads)
- ✅ Reconnaissance (Port scans, OS fingerprinting)

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) file for details.

---

## 📞 Support

For support, documentation, and community:
- **GitHub Issues**: [Report bugs](https://github.com/kushalshrestha303-web/fortress-xdr-ai/issues)
- **Documentation**: [Read docs](./docs)
- **Email**: support@fortressxdr.ai

---

## 🌟 Acknowledgments

Built with inspiration from:
- MITRE ATT&CK Framework
- Wazuh Open Source SIEM
- NIST Cybersecurity Framework
- Enterprise SOC best practices

---

**Fortress XDR AI** - Elevating Enterprise Security Operations 🛡️
