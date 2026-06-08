"""Detection engine with rule-based threat detection"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta

class DetectionEngine:
    """Engine for detecting security threats using rules"""
    
    def __init__(self):
        """Initialize detection engine"""
        self.rules = self._load_detection_rules()
    
    def _load_detection_rules(self) -> List[Dict]:
        """Load detection rules"""
        return [
            # Brute Force Detection Rule
            {
                "id": "rule_001",
                "name": "Brute Force Attack Detection",
                "severity": "critical",
                "description": "Detects multiple failed login attempts indicating brute force attack",
                "type": "threshold",
                "condition": {
                    "field": "event_id",
                    "value": [4625, 4771],  # Windows failed login events
                    "operator": "in"
                },
                "aggregation": {
                    "field": "source_ip",
                    "threshold": 10,
                    "timeframe": 300  # 5 minutes
                },
                "mitre_techniques": ["T1110", "T1078"],
                "tactics": ["credential-access"]
            },
            # Suspicious PowerShell Rule
            {
                "id": "rule_002",
                "name": "Suspicious PowerShell Execution",
                "severity": "critical",
                "description": "Detects suspicious PowerShell commands with encoded scripts or downloads",
                "type": "keyword",
                "condition": {
                    "field": "process_name",
                    "value": "powershell.exe",
                    "operator": "equals"
                },
                "additional_conditions": [
                    {"field": "command_line", "value": ["DownloadString", "IEX", "-enc"], "operator": "contains_any"}
                ],
                "mitre_techniques": ["T1059.001", "T1027"],
                "tactics": ["execution", "defense-evasion"]
            },
            # Lateral Movement via WinRM
            {
                "id": "rule_003",
                "name": "Lateral Movement via WinRM",
                "severity": "high",
                "description": "Detects potential lateral movement using Windows Remote Management",
                "type": "keyword",
                "condition": {
                    "field": "process_name",
                    "value": ["winrm.exe", "wsmprovhost.exe"],
                    "operator": "in"
                },
                "mitre_techniques": ["T1021.006"],
                "tactics": ["lateral-movement"]
            },
            # Data Exfiltration Detection
            {
                "id": "rule_004",
                "name": "Suspicious Data Transfer",
                "severity": "high",
                "description": "Detects large data transfers to external IPs",
                "type": "threshold",
                "condition": {
                    "field": "network.bytes_out",
                    "value": 100000000,  # 100 MB
                    "operator": "greater_than"
                },
                "aggregation": {
                    "field": "destination_ip",
                    "threshold": 1,
                    "timeframe": 3600  # 1 hour
                },
                "mitre_techniques": ["T1048"],
                "tactics": ["exfiltration"]
            },
            # Process Injection Detection
            {
                "id": "rule_005",
                "name": "Suspicious Process Injection",
                "severity": "critical",
                "description": "Detects process injection or code injection attempts",
                "type": "keyword",
                "condition": {
                    "field": "event_id",
                    "value": [8, 10],  # Sysmon CreateRemoteThread, ProcessAccess
                    "operator": "in"
                },
                "additional_conditions": [
                    {"field": "source_process", "value": ["explorer.exe", "svchost.exe"], "operator": "not_in"}
                ],
                "mitre_techniques": ["T1055"],
                "tactics": ["defense-evasion", "privilege-escalation"]
            },
            # Registry Persistence Detection
            {
                "id": "rule_006",
                "name": "Registry Persistence Mechanism",
                "severity": "high",
                "description": "Detects modifications to registry run keys for persistence",
                "type": "keyword",
                "condition": {
                    "field": "event_id",
                    "value": 4657,  # Registry value modification
                    "operator": "equals"
                },
                "additional_conditions": [
                    {"field": "registry_path", "value": ["*Run", "*RunOnce"], "operator": "contains_any"}
                ],
                "mitre_techniques": ["T1547.001"],
                "tactics": ["persistence"]
            },
            # Credential Dumping Detection
            {
                "id": "rule_007",
                "name": "Credential Dumping Attempt",
                "severity": "critical",
                "description": "Detects Mimikatz or credential extraction attempts",
                "type": "keyword",
                "condition": {
                    "field": "process_name",
                    "value": ["mimikatz.exe", "procdump.exe"],
                    "operator": "in"
                },
                "mitre_techniques": ["T1003"],
                "tactics": ["credential-access"]
            },
            # DNS Tunneling Detection
            {
                "id": "rule_008",
                "name": "DNS Tunneling Communication",
                "severity": "high",
                "description": "Detects DNS tunneling for command and control",
                "type": "anomaly",
                "condition": {
                    "field": "dns_query_length",
                    "value": 100,  # Unusually long DNS queries
                    "operator": "greater_than"
                },
                "mitre_techniques": ["T1071.004"],
                "tactics": ["command-and-control"]
            },
            # Living Off The Land Detection
            {
                "id": "rule_009",
                "name": "Living Off The Land Attack",
                "severity": "high",
                "description": "Detects misuse of legitimate tools for attacks",
                "type": "keyword",
                "condition": {
                    "field": "process_name",
                    "value": ["certutil.exe", "bitsadmin.exe", "wevtutil.exe"],
                    "operator": "in"
                },
                "additional_conditions": [
                    {"field": "command_line", "value": ["download", "decode", "urlcache"], "operator": "contains_any"}
                ],
                "mitre_techniques": ["T1218"],
                "tactics": ["defense-evasion", "execution"]
            },
            # Port Scanning Detection
            {
                "id": "rule_010",
                "name": "Port Scanning Activity",
                "severity": "medium",
                "description": "Detects network port scanning",
                "type": "threshold",
                "condition": {
                    "field": "network.destination_port",
                    "value": "*",
                    "operator": "contains"
                },
                "aggregation": {
                    "field": "network.destination_port",
                    "threshold": 50,  # Scanning multiple ports
                    "timeframe": 300
                },
                "mitre_techniques": ["T1046"],
                "tactics": ["discovery"]
            }
        ]
    
    def detect_threats(self, event: Dict) -> List[Dict]:
        """Detect threats in security event"""
        detected_threats = []
        
        for rule in self.rules:
            if self._evaluate_rule(rule, event):
                detected_threats.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "mitre_techniques": rule.get("mitre_techniques", []),
                    "tactics": rule.get("tactics", []),
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return detected_threats
    
    def _evaluate_rule(self, rule: Dict, event: Dict) -> bool:
        """Evaluate if event matches rule"""
        condition = rule.get("condition", {})
        
        # Evaluate main condition
        if not self._evaluate_condition(condition, event):
            return False
        
        # Evaluate additional conditions
        for additional in rule.get("additional_conditions", []):
            if not self._evaluate_condition(additional, event):
                return False
        
        return True
    
    def _evaluate_condition(self, condition: Dict, event: Dict) -> bool:
        """Evaluate a single condition"""
        field = condition.get("field")
        value = condition.get("value")
        operator = condition.get("operator")
        
        event_value = event.get(field)
        
        if operator == "equals":
            return event_value == value
        elif operator == "in":
            return event_value in value
        elif operator == "not_in":
            return event_value not in value
        elif operator == "contains":
            return value in str(event_value)
        elif operator == "contains_any":
            return any(v in str(event_value) for v in value)
        elif operator == "greater_than":
            return float(event_value or 0) > float(value or 0)
        elif operator == "less_than":
            return float(event_value or 0) < float(value or 0)
        
        return False
    
    def get_rule(self, rule_id: str) -> Optional[Dict]:
        """Get specific detection rule"""
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None
    
    def get_all_rules(self) -> List[Dict]:
        """Get all detection rules"""
        return self.rules
