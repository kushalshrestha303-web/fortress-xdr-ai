# Threat Hunting Guide

## Hunt Templates

### 1. PowerShell Abuse

```kql
process.name: powershell AND 
(command_line: *DownloadString* OR 
 command_line: *IEX* OR 
 command_line: *Invoke-Expression*)
```

### 2. Ransomware Detection

```kql
(file.extension: *.encrypted OR 
 process.name: *crypt* OR 
 registry.path: *HKLM\System*) AND 
process.parent.name: explorer.exe
```

### 3. Lateral Movement

```kql
network.protocol: smb AND 
process.name: (psexec* OR wmiexec* OR smbexec*)
```

### 4. Data Exfiltration

```kql
network.bytes_out: >100000000 AND 
network.destination.geo.country_name: !YOUR_COUNTRY
```

## Natural Language Queries

```
"Show all failed login attempts in the last 24 hours"
"Find suspicious PowerShell execution with encoded commands"
"Show processes spawned from Office applications"
"List all outbound connections to unknown IPs"
```
