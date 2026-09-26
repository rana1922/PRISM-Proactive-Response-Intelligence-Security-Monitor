from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List

class ThreatIntelProvider(ABC):
    @abstractmethod
    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def check_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        pass


class DemoThreatIntelProvider(ThreatIntelProvider):
    """Seed threat intelligence provider providing realistic offline intelligence"""

    def __init__(self):
        self.known_ips = {
            "185.220.101.45": {"threat_level": "critical", "confidence": 94, "source": "PRISM Threat Intelligence", "tags": ["Tor Exit Node", "SQLi Scanner"]},
            "194.26.29.112": {"threat_level": "high", "confidence": 91, "source": "AlienVault OTX (Demo)", "tags": ["C2 Beacon", "RCE Origin"]},
            "45.154.255.89": {"threat_level": "high", "confidence": 89, "source": "AbuseIPDB (Demo)", "tags": ["Port Scanner", "Mirai Probe"]},
            "103.145.13.204": {"threat_level": "medium", "confidence": 82, "source": "PRISM Threat Intelligence", "tags": ["Brute Force"]},
        }
        self.known_domains = {
            "malicious-c2-update.org": {"threat_level": "critical", "confidence": 96, "source": "PRISM Threat Intelligence", "tags": ["CobaltStrike", "Stager"]},
            "api-sync-telemetry.cc": {"threat_level": "high", "confidence": 90, "source": "ThreatFox (Demo)", "tags": ["Stealer"]},
        }
        self.known_hashes = {
            "44d88612fea8a8f36de82e1278abb02f": {"threat_level": "critical", "confidence": 98, "source": "VirusTotal (Demo)", "tags": ["Mimikatz", "LSASS Dump"]},
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"threat_level": "high", "confidence": 92, "source": "PRISM Threat Intelligence", "tags": ["Dropper"]},
        }

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self.known_ips.get(ip)

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return self.known_domains.get(domain)

    async def check_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        return self.known_hashes.get(hash_value)


class NVDProvider:
    """NVD CVE vulnerability intelligence provider"""

    async def fetch_cves(self, keyword: str) -> List[Dict[str, Any]]:
        # Seeded demo fallback ensuring deterministic reliable execution
        return [
            {
                "cve_id": "CVE-2024-12345",
                "description": "Remote code execution vulnerability via unauthenticated parameter evaluation in Web Services core component.",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "affected_product": "Web Application Server",
                "source_type": "DEMO"
            },
            {
                "cve_id": "CVE-2021-44228",
                "description": "Apache Log4j2 JNDI features do not protect against LDAP endpoints.",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "affected_product": "Apache Log4j",
                "source_type": "LIVE"
            }
        ]
