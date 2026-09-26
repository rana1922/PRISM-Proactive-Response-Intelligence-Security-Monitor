import re
from typing import Optional, Dict, Any, List

class DetectionEngine:
    """PRISM Security Event Attack Detection Engine"""

    def __init__(self):
        self.sql_patterns = [
            re.compile(r"'\s*OR\s*['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
            re.compile(r"UNION\s+SELECT", re.IGNORECASE),
            re.compile(r"SELECT\s+\*\s+FROM", re.IGNORECASE),
            re.compile(r"DROP\s+TABLE", re.IGNORECASE),
            re.compile(r"INSERT\s+INTO", re.IGNORECASE),
            re.compile(r"information_schema", re.IGNORECASE),
            re.compile(r"--\s*$", re.IGNORECASE),
            re.compile(r"xp_cmdshell", re.IGNORECASE),
            re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
            re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
            re.compile(r"SLEEP\s*\(\d+\)", re.IGNORECASE),
        ]

        self.rce_patterns = [
            re.compile(r"cmd\.exe", re.IGNORECASE),
            re.compile(r"powershell(\.exe)?\s+(-enc|-c|iex)", re.IGNORECASE),
            re.compile(r"/bin/bash", re.IGNORECASE),
            re.compile(r"/bin/sh", re.IGNORECASE),
            re.compile(r"\bwget\b", re.IGNORECASE),
            re.compile(r"\bcurl\b", re.IGNORECASE),
            re.compile(r"\bnc\s+(-e|-l|-p|\d+)", re.IGNORECASE),
            re.compile(r"python\s+-c", re.IGNORECASE),
            re.compile(r"bash\s+-c", re.IGNORECASE),
            re.compile(r"whoami", re.IGNORECASE),
            re.compile(r"cat\s+/etc/passwd", re.IGNORECASE),
            re.compile(r"rm\s+-rf", re.IGNORECASE),
        ]

        self.malware_keywords = [
            "mimikatz", "cobaltstrike", "covenant", "wannacry", 
            "trickbot", "redline", "meterpreter", "beacon.exe", "payload.sh"
        ]

        self.auth_failures: Dict[str, int] = {}
        self.port_scan_history: Dict[str, set] = {}

    def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_target = " ".join([
            str(event.get("url") or ""),
            str(event.get("payload") or ""),
            str(event.get("process_command") or ""),
            str(event.get("process_name") or ""),
            str(event.get("user_agent") or ""),
            str(event.get("domain") or "")
        ])

        # 1. SQL Injection
        matched_sql = [p.pattern for p in self.sql_patterns if p.search(raw_target)]
        if matched_sql:
            return {
                "attack_type": "SQL_INJECTION",
                "confidence": min(90 + len(matched_sql) * 2, 98),
                "rule_id": "PRISM-SQL-001",
                "rule_name": "SQL Injection Attack Detection",
                "matched_patterns": matched_sql,
                "description": f"SQL Injection syntax detected matching pattern {matched_sql[0]}"
            }

        # 2. RCE
        matched_rce = [p.pattern for p in self.rce_patterns if p.search(raw_target)]
        if matched_rce:
            return {
                "attack_type": "RCE",
                "confidence": min(92 + len(matched_rce) * 2, 98),
                "rule_id": "PRISM-RCE-001",
                "rule_name": "Remote Code Execution Pattern",
                "matched_patterns": matched_rce,
                "description": f"Remote command execution invocation detected: {matched_rce[0]}"
            }

        # 3. Malware
        matched_mal = [kw for kw in self.malware_keywords if kw in raw_target.lower()]
        if matched_mal or event.get("file_hash") == "44d88612fea8a8f36de82e1278abb02f":
            return {
                "attack_type": "MALWARE",
                "confidence": 94,
                "rule_id": "PRISM-MAL-001",
                "rule_name": "Malware & Trojan Signature Detection",
                "matched_patterns": matched_mal or [event.get("file_hash", "")],
                "description": "Known malware hash/payload signature identified"
            }

        # 4. Brute Force
        if event.get("event_type") == "auth_event" or (event.get("url") and "/login" in event.get("url")):
            ip = event.get("source_ip", "")
            self.auth_failures[ip] = self.auth_failures.get(ip, 0) + 1
            if self.auth_failures[ip] >= 3 or (event.get("payload") and "admin:" in event.get("payload")):
                return {
                    "attack_type": "BRUTE_FORCE",
                    "confidence": 90,
                    "rule_id": "PRISM-BF-001",
                    "rule_name": "Authentication Brute Force Detection",
                    "matched_patterns": [f"Multiple auth attempts from {ip}"],
                    "description": f"Repeated failed authentication attempts from IP {ip}"
                }

        # 5. Port Scan
        if event.get("event_type") == "network_event" or event.get("destination_port"):
            ip = event.get("source_ip", "")
            ports = self.port_scan_history.setdefault(ip, set())
            if event.get("destination_port"):
                ports.add(event.get("destination_port"))
            if len(ports) >= 3 or (event.get("payload") and "SYN probe" in event.get("payload")):
                return {
                    "attack_type": "PORT_SCAN",
                    "confidence": 88,
                    "rule_id": "PRISM-SCAN-001",
                    "rule_name": "Network Port Scanning & Reconnaissance",
                    "matched_patterns": [f"Probed ports: {list(ports)}"],
                    "description": "Port scanning reconnaissance detected probing multiple endpoints"
                }

        return None
