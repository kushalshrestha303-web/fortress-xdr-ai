# Comprehensive Threat Hunting Guide

## Overview

Fortress XDR AI supports threat hunting with:
- **KQL (Kibana Query Language)** - OpenSearch queries
- **Sigma Rules** - Portable detection rules
- **YARA Rules** - File scanning rules
- **Natural Language** - Conversational queries
- **Wazuh Queries** - Wazuh-native queries
- **OpenSearch DSL** - Advanced JSON queries

## Hunt Templates

### 1. PowerShell Abuse

**Purpose**: Detect suspicious PowerShell execution patterns

**KQL Query**:
```kql
process.name:"powershell.exe" AND 
(command_line:"DownloadString" OR 
 command_line:"IEX" OR 
 command_line:"-enc" OR 
 command_line:"Invoke-Expression")
```

**Sigma Rule**:
```yaml
title: Suspicious PowerShell Execution
detection:
  selection:
    process_name: powershell.exe
    command_line:
      - '*DownloadString*'
      - '*IEX*'
      - '*Invoke-Expression*'
      - '*-enc*'
      - '*-EncodedCommand*'
  condition: selection
severity: high
```

**MITRE Techniques**: T1059.001, T1027

**API Usage**:
```bash
curl -X POST http://localhost:8000/api/v1/hunts/execute \
  -H "Authorization: Bearer TOKEN" \
  -d '{
    "query_type": "kql",
    "query": "process.name:\"powershell.exe\" AND command_line:\"DownloadString\"",
    "timeframe": "24h"
  }'
```

### 2. Ransomware Detection

**Purpose**: Identify ransomware indicators of compromise

**KQL Query**:
```kql
(file.extension:(".encrypted" OR ".locked" OR ".payment") OR 
process.name:(*crypt* OR *ransom*)) AND 
parent_process:"explorer.exe"
```

**MITRE Techniques**: T1486, T1204

**Severity**: Critical

### 3. Lateral Movement

**Purpose**: Detect PsExec, Pass-the-Hash, and SMB exploitation

**KQL Query**:
```kql
(process.name:("psexec*.exe" OR "psexec*.cmd") OR 
network.destination_port:445 OR 
process.command_line:"*\\\\*admin$*") AND 
source_ip:*
```

**MITRE Techniques**: T1021.002, T1550

**Detection Indicators**:
- PsExec process execution
- SMB port 445 connections
- Admin share access patterns
- Service creation events

### 4. Data Exfiltration

**Purpose**: Detect suspicious data transfers

**KQL Query**:
```kql
network.bytes_out:>100000000 AND 
(destination_country:!"US" OR destination_ip:"*.*.*.*") AND 
process.name:(*chrome* OR *firefox* OR *7z* OR *rar*)
```

**MITRE Techniques**: T1048, T1041

**Thresholds**:
- Data volume: >100 MB/hour
- Destination: External IP addresses
- Process: Compression or browser tools

### 5. Credential Dumping

**Purpose**: Detect Mimikatz and credential extraction

**KQL Query**:
```kql
(process.name:("mimikatz.exe" OR "lsass.exe") OR 
process.parent:"lsass.exe" OR 
command_line:(*sekurlsa* OR *logonpasswords* OR *dcync*)) AND 
event_type:"process_access"
```

**MITRE Techniques**: T1003, T1558

**Indicators**:
- Mimikatz execution
- LSASS access attempts
- Kerberos cache access
- Registry hive dumping

### 6. Reconnaissance

**Purpose**: Detect port scanning and enumeration

**KQL Query**:
```kql
(process.name:("nmap*" OR "net.exe" OR "netstat.exe") OR 
command_line:("nmap -sS" OR "net view" OR "netstat -ano")) AND 
parent_process:"cmd.exe"
```

**MITRE Techniques**: T1046, T1018

## Natural Language Hunt Examples

### Query 1: PowerShell Abuse Hunt
```
"Show all PowerShell commands executed in the last 24 hours that contain DownloadString or IEX"

Converted to KQL:
process.name:powershell.exe AND 
(command_line:DownloadString OR command_line:IEX) AND 
timestamp:[now-24h TO now]
```

### Query 2: Suspicious File Extension Hunt
```
"Find all files created with unusual extensions like .encrypted, .locked, .payment in the last week"

Converted to KQL:
file.extension:(".encrypted" OR ".locked" OR ".payment") AND 
event_type:file_creation AND 
timestamp:[now-7d TO now]
```

### Query 3: Admin Account Hunt
```
"Show failed login attempts to admin accounts from the last 12 hours"

Converted to KQL:
event_id:4625 AND 
target_user:(admin OR administrator OR root) AND 
timestamp:[now-12h TO now]
```

### Query 4: Network Anomaly Hunt
```
"Find outbound connections to non-standard ports above 5000 bytes in last 3 hours"

Converted to KQL:
network.direction:outbound AND 
network.destination_port:>5000 AND 
network.bytes:>5000 AND 
timestamp:[now-3h TO now]
```

## Detection Rules

### Rule 1: Brute Force Attack
```yaml
id: rule_001
name: Brute Force Attack Detection
severity: critical
type: threshold
condition:
  field: event_id
  value: [4625, 4771]
  operator: in
aggregation:
  field: source_ip
  threshold: 10 failures
  timeframe: 300 seconds
mitre_techniques: [T1110, T1078]
tactics: [credential-access]
```

### Rule 2: Suspicious Process Injection
```yaml
id: rule_005
name: Suspicious Process Injection
severity: critical
type: keyword
condition:
  field: event_id
  value: [8, 10]
  operator: in
additional_conditions:
  - field: source_process
    value: [explorer.exe, svchost.exe]
    operator: not_in
mitre_techniques: [T1055]
tactics: [defense-evasion, privilege-escalation]
```

## API Endpoints

### List Hunt Templates
```bash
GET /api/v1/hunts/templates
```

### Execute Hunt
```bash
POST /api/v1/hunts/execute
Body: {"query_type": "kql", "query": "...", "timeframe": "24h"}
```

### Execute Template Hunt
```bash
POST /api/v1/hunts/template-execute
Body: {"template_name": "powershell_abuse"}
```

### List Detection Rules
```bash
GET /api/v1/detection-rules
```

### Get Detection Rule Details
```bash
GET /api/v1/detection-rules/{rule_id}
```

## Best Practices

1. **Start with Templates**: Use pre-built templates for common hunts
2. **Use Appropriate Query Language**: 
   - KQL for OpenSearch
   - Sigma for portable rules
   - Natural language for exploratory hunts
3. **Set Appropriate Timeframes**: Longer timeframes = more comprehensive but slower
4. **Review Results Carefully**: Not all matches are true positives
5. **Document Findings**: Track what you hunted and what you found
6. **Iterate**: Refine queries based on results

## Hunt Workflow

```
1. Identify Threat → Select Template or Create Query
         ↓
2. Execute Hunt → Run against historical data
         ↓
3. Review Results → Analyze matches for true positives
         ↓
4. Investigate → Drill down on findings
         ↓
5. Map to MITRE → Identify tactics and techniques
         ↓
6. Document → Create incident report
         ↓
7. Respond → Take remediation actions
```
