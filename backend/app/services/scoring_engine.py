from typing import Dict, Any, List

class ScoringEngine:
    """Explainable Threat Scoring Engine (0-100)"""

    def calculate_score(
        self,
        event: Dict[str, Any],
        attack_type: str,
        confidence_pct: int,
        ioc_match: bool,
        ioc_threat_level: str,
        cve_match: bool,
        cvss_score: float,
        asset_criticality_score: int
    ) -> Dict[str, Any]:
        reasons: List[str] = []

        # 1. Base attack severity: 0-40
        attack_scores = {
            "RCE": 40,
            "MALWARE": 38,
            "SQL_INJECTION": 35,
            "BRUTE_FORCE": 25,
            "PORT_SCAN": 20,
        }
        attack_score = attack_scores.get(attack_type, 15)
        reasons.append(f"{attack_type} pattern confirmed (+{attack_score})")

        # 2. IOC match: 0-25
        ioc_score = 0
        if ioc_match:
            if ioc_threat_level == "critical":
                ioc_score = 25
            elif ioc_threat_level == "high":
                ioc_score = 20
            else:
                ioc_score = 12
            reasons.append(f"Matched {ioc_threat_level.upper()} threat IOC (+{ioc_score})")

        # 3. CVE correlation: 0-20
        cve_score = 0
        if cve_match:
            if cvss_score >= 9.0:
                cve_score = 20
            elif cvss_score >= 7.0:
                cve_score = 15
            else:
                cve_score = 10
            reasons.append(f"Correlated with CVE vulnerability (CVSS {cvss_score}) (+{cve_score})")

        # 4. Asset criticality: 0-10
        asset_score = min(asset_criticality_score, 10) if asset_criticality_score else 5
        reasons.append(f"Target asset criticality weight (+{asset_score})")

        # 5. Behavior confidence: 0-5
        if confidence_pct >= 95:
            conf_score = 5
        elif confidence_pct >= 90:
            conf_score = 4
        elif confidence_pct >= 80:
            conf_score = 3
        else:
            conf_score = 2
        reasons.append(f"Detection confidence {confidence_pct}% (+{conf_score})")

        total = min(attack_score + ioc_score + cve_score + asset_score + conf_score, 100)

        severity = "LOW"
        if total >= 80:
            severity = "CRITICAL"
        elif total >= 60:
            severity = "HIGH"
        elif total >= 30:
            severity = "MEDIUM"

        return {
            "attack_score": attack_score,
            "attack_type": attack_type,
            "ioc_score": ioc_score,
            "cve_score": cve_score,
            "asset_score": asset_score,
            "confidence_score": conf_score,
            "confidence_pct": confidence_pct,
            "total_score": total,
            "severity": severity,
            "reasons": reasons
        }


class ResponseEngine:
    """Safe Simulation Automated Response Engine"""

    def __init__(self, mode: str = "simulation"):
        self.mode = mode.upper()

    def evaluate_response(self, threat_score: int, severity: str, source_ip: str, hostname: str) -> Dict[str, Any]:
        recommended: List[str] = []
        executed: List[str] = []

        if threat_score < 30:
            pass  # Monitor
        elif threat_score < 60:
            recommended.append("CREATE_INCIDENT")
        elif threat_score < 80:
            recommended.extend(["CREATE_INCIDENT", "BLOCK_IP"])
            executed.append("CREATE_INCIDENT")
        else:
            recommended.extend(["CREATE_INCIDENT", "BLOCK_IP", "ISOLATE_HOST", "ESCALATE_SOC"])
            executed.extend(["CREATE_INCIDENT", "BLOCK_IP", "ISOLATE_HOST", "ESCALATE_SOC"])

        return {
            "recommended": recommended,
            "executed": executed,
            "mode": self.mode,
            "should_escalate_soc": "ESCALATE_SOC" in executed,
            "should_block_ip": "BLOCK_IP" in executed,
            "should_isolate_host": "ISOLATE_HOST" in executed
        }
