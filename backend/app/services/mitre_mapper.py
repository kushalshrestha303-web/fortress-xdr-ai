"""MITRE ATT&CK Framework mapping service"""

from typing import List, Dict, Optional
from enum import Enum
import json

class MITRETactic(str, Enum):
    """MITRE ATT&CK Tactics"""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class MitreMapper:
    """Maps security events to MITRE ATT&CK framework"""
    
    def __init__(self):
        """Initialize MITRE technique mappings"""
        self.technique_map = self._load_techniques()
        self.signature_patterns = self._load_patterns()
    
    def _load_techniques(self) -> Dict:
        """Load MITRE ATT&CK techniques database"""
        return {
            # Execution Techniques
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "execution",
                "subtechniques": {
                    "T1059.001": "PowerShell",
                    "T1059.003": "Windows Command Shell",
                    "T1059.004": "Unix Shell",
                    "T1059.007": "JavaScript/Jscript"
                }
            },
            "T1086": {
                "name": "PowerShell",
                "tactic": "execution",
                "retired": True,  # Merged into T1059.001
                "merged_to": "T1059.001"
            },
            "T1204": {
                "name": "User Execution",
                "tactic": "execution",
                "subtechniques": {
                    "T1204.001": "Malicious Link",
                    "T1204.002": "Malicious File",
                    "T1204.003": "Malicious Image"
                }
            },
            
            # Credential Access
            "T1110": {
                "name": "Brute Force",
                "tactic": "credential-access",
                "subtechniques": {
                    "T1110.001": "Password Guessing",
                    "T1110.002": "Password Spraying",
                    "T1110.003": "Password Stuffing",
                    "T1110.004": "Credential Stuffing"
                }
            },
            "T1187": {
                "name": "Forced Authentication",
                "tactic": "credential-access"
            },
            "T1111": {
                "name": "Multi-Stage Channels",
                "tactic": "command-and-control"
            },
            "T1056": {
                "name": "Input Capture",
                "tactic": "collection",
                "subtechniques": {
                    "T1056.001": "Keylogging",
                    "T1056.004": "Credential API Hooking"
                }
            },
            
            # Lateral Movement
            "T1021": {
                "name": "Remote Services",
                "tactic": "lateral-movement",
                "subtechniques": {
                    "T1021.001": "Remote Services: Telnet",
                    "T1021.002": "Remote Services: SSH",
                    "T1021.004": "Remote Services: SSH",
                    "T1021.006": "Remote Services: Windows Remote Management"
                }
            },
            "T1570": {
                "name": "Lateral Tool Transfer",
                "tactic": "lateral-movement"
            },
            
            # Defense Evasion
            "T1197": {
                "name": "BITS Jobs",
                "tactic": "defense-evasion"
            },
            "T1036": {
                "name": "Masquerading",
                "tactic": "defense-evasion",
                "subtechniques": {
                    "T1036.003": "Rename System Utilities",
                    "T1036.004": "Masquerade Task or Service"
                }
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "tactic": "defense-evasion",
                "subtechniques": {
                    "T1027.001": "Binary Padding",
                    "T1027.010": "Command Obfuscation"
                }
            },
            "T1140": {
                "name": "Deobfuscate/Decode Files or Information",
                "tactic": "defense-evasion"
            },
            
            # Persistence
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "tactic": "persistence",
                "subtechniques": {
                    "T1547.001": "Registry Run Keys / Startup Folder",
                    "T1547.012": "Print Processors"
                }
            },
            "T1543": {
                "name": "Create or Modify System Process",
                "tactic": "persistence",
                "subtechniques": {
                    "T1543.003": "Windows Service"
                }
            },
            
            # Command & Control
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "command-and-control",
                "subtechniques": {
                    "T1071.001": "Web Protocols",
                    "T1071.004": "DNS"
                }
            },
            "T1572": {
                "name": "Protocol Tunneling",
                "tactic": "command-and-control"
            },
            
            # Exfiltration
            "T1020": {
                "name": "Automated Exfiltration",
                "tactic": "exfiltration"
            },
            "T1048": {
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "exfiltration",
                "subtechniques": {
                    "T1048.001": "Exfiltration Over Synchronous Web Protocol",
                    "T1048.002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol"
                }
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration"
            },
            
            # Privilege Escalation
            "T1134": {
                "name": "Access Token Manipulation",
                "tactic": "privilege-escalation",
                "subtechniques": {
                    "T1134.003": "Make and Impersonate Token",
                    "T1134.004": "Parent PID Spoofing"
                }
            },
            "T1547": {
                "name": "Exploitation for Privilege Escalation",
                "tactic": "privilege-escalation"
            }
        }
    
    def _load_patterns(self) -> Dict:
        """Load signature patterns for technique detection"""
        return {
            "T1059.001": {  # PowerShell
                "processes": ["powershell.exe", "pwsh.exe"],
                "keywords": ["DownloadString", "IEX", "Invoke-Expression", "Invoke-WebRequest", "-enc", "-EncodedCommand"],
                "registry": ["HKLM\\Software\\Microsoft\\PowerShell"]
            },
            "T1110": {  # Brute Force
                "event_ids": [4625, 4771],  # Failed login
                "threshold": {"count": 10, "timeframe": 300},  # 10 failures in 5 min
                "keywords": ["failed login", "invalid credentials", "access denied"]
            },
            "T1021.006": {  # WinRM
                "processes": ["winrm.exe", "wsmprovhost.exe"],
                "ports": [5985, 5986],
                "event_ids": [4688]  # Process creation
            },
            "T1197": {  # BITS Jobs
                "processes": ["bitsadmin.exe"],
                "keywords": ["transfer", "resume", "create"]
            },
            "T1547.001": {  # Registry Run Keys
                "registry_paths": [
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                ]
            },
            "T1071.001": {  # Web Protocols C2
                "network_protocols": ["http", "https"],
                "suspicious_domains": [],
                "user_agents": ["python-requests", "curl", "wget"]
            },
            "T1048.001": {  # Exfiltration Over HTTPS
                "protocol": "https",
                "data_volume": {"threshold": 100_000_000, "timeframe": 3600}  # 100MB/hour
            }
        }
    
    def map_alert_to_techniques(self, alert: Dict) -> List[Dict]:
        """Map alert data to MITRE ATT&CK techniques"""
        matched_techniques = []
        
        # Check process name
        if "process_name" in alert:
            matched_techniques.extend(
                self._match_process(alert["process_name"])
            )
        
        # Check command line
        if "command_line" in alert:
            matched_techniques.extend(
                self._match_command_line(alert["command_line"])
            )
        
        # Check event type
        if "event_type" in alert:
            matched_techniques.extend(
                self._match_event_type(alert["event_type"])
            )
        
        # Check network activity
        if "network" in alert:
            matched_techniques.extend(
                self._match_network(alert["network"])
            )
        
        # Remove duplicates
        seen = set()
        unique_techniques = []
        for technique in matched_techniques:
            key = technique.get("id")
            if key not in seen:
                seen.add(key)
                unique_techniques.append(technique)
        
        return unique_techniques
    
    def _match_process(self, process_name: str) -> List[Dict]:
        """Match process name to techniques"""
        matched = []
        process_lower = process_name.lower()
        
        for technique_id, patterns in self.signature_patterns.items():
            if "processes" in patterns:
                for proc in patterns["processes"]:
                    if proc.lower() in process_lower or process_lower in proc.lower():
                        matched.append(self._format_technique(technique_id))
        
        return matched
    
    def _match_command_line(self, command_line: str) -> List[Dict]:
        """Match command line to techniques"""
        matched = []
        cmd_lower = command_line.lower()
        
        for technique_id, patterns in self.signature_patterns.items():
            if "keywords" in patterns:
                for keyword in patterns["keywords"]:
                    if keyword.lower() in cmd_lower:
                        matched.append(self._format_technique(technique_id))
        
        return matched
    
    def _match_event_type(self, event_type: str) -> List[Dict]:
        """Match event type to techniques"""
        matched = []
        
        # Map Windows event IDs to techniques
        event_id_mapping = {
            4625: "T1110",      # Failed login -> Brute Force
            4771: "T1110",      # Kerberos failure -> Brute Force
            4688: "T1059",      # Process creation -> Command Execution
            4697: "T1543.003",  # Service created -> Windows Service
            4657: "T1547.001",  # Registry modified -> Registry Run Keys
        }
        
        if event_type in event_id_mapping:
            matched.append(
                self._format_technique(event_id_mapping[event_type])
            )
        
        return matched
    
    def _match_network(self, network_data: Dict) -> List[Dict]:
        """Match network activity to techniques"""
        matched = []
        
        # Check for C2 communication patterns
        if network_data.get("destination_port") in [443, 80, 8080, 8443]:
            matched.append(self._format_technique("T1071.001"))  # Web Protocols
        
        if network_data.get("protocol") == "dns":
            matched.append(self._format_technique("T1071.004"))  # DNS
        
        if network_data.get("bytes_out", 0) > 100_000_000:
            matched.append(self._format_technique("T1048.001"))  # Exfiltration
        
        return matched
    
    def _format_technique(self, technique_id: str) -> Dict:
        """Format technique information"""
        if technique_id in self.technique_map:
            tech = self.technique_map[technique_id]
            return {
                "id": technique_id,
                "name": tech.get("name"),
                "tactic": tech.get("tactic"),
                "subtechniques": tech.get("subtechniques", {}),
                "severity": self._calculate_severity(technique_id)
            }
        return {"id": technique_id, "name": "Unknown", "severity": "medium"}
    
    def _calculate_severity(self, technique_id: str) -> str:
        """Calculate severity based on technique"""
        critical_techniques = [
            "T1110",      # Brute Force
            "T1059.001",  # PowerShell
            "T1134.003",  # Token Impersonation
            "T1021.002",  # SSH
        ]
        
        high_techniques = [
            "T1071.001",  # Web Protocols C2
            "T1048.001",  # Exfiltration
            "T1547.001",  # Registry Run Keys
        ]
        
        if technique_id in critical_techniques:
            return "critical"
        elif technique_id in high_techniques:
            return "high"
        else:
            return "medium"
    
    def get_attack_chain(self, techniques: List[str]) -> List[Dict]:
        """Get MITRE ATT&CK chain order"""
        tactic_order = [
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact"
        ]
        
        # Group techniques by tactic
        tactic_techniques = {}
        for technique_id in techniques:
            if technique_id in self.technique_map:
                tech = self.technique_map[technique_id]
                tactic = tech.get("tactic")
                if tactic:
                    if tactic not in tactic_techniques:
                        tactic_techniques[tactic] = []
                    tactic_techniques[tactic].append(technique_id)
        
        # Order by attack chain
        chain = []
        for tactic in tactic_order:
            if tactic in tactic_techniques:
                chain.append({
                    "tactic": tactic,
                    "techniques": tactic_techniques[tactic]
                })
        
        return chain
