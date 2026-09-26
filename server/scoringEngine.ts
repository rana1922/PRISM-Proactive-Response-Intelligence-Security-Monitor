import { AttackType, SeverityLevel, ScoreFactors, SecurityEvent } from './types';
import { db } from './db';
import { IOCMatchResult } from './iocEngine';
import { CVEMatchResult } from './cveEngine';

export class ScoringEngine {
  public calculateScore(
    event: SecurityEvent,
    attackType: AttackType,
    confidencePct: number,
    iocMatch: IOCMatchResult,
    cveMatch: CVEMatchResult
  ): ScoreFactors {
    const reasons: string[] = [];

    // 1. Base attack severity: 0–40
    let attackScore = 0;
    switch (attackType) {
      case 'RCE':
        attackScore = 40;
        reasons.push('Remote Code Execution attempt identified (+40)');
        break;
      case 'MALWARE':
        attackScore = 38;
        reasons.push('Malware / Trojan execution payload identified (+38)');
        break;
      case 'SQL_INJECTION':
        attackScore = 35;
        reasons.push('SQL Injection syntax matched active rule (+35)');
        break;
      case 'BRUTE_FORCE':
        attackScore = 25;
        reasons.push('Brute-force authentication flood (+25)');
        break;
      case 'PORT_SCAN':
        attackScore = 20;
        reasons.push('Port scan reconnaissance detected (+20)');
        break;
      default:
        attackScore = 15;
        reasons.push('Suspicious anomalous pattern (+15)');
    }

    // 2. IOC match: 0–25
    let iocScore = 0;
    let iocMatchedStr: string | undefined = undefined;
    if (iocMatch.matched && iocMatch.ioc_record) {
      iocMatchedStr = `${iocMatch.ioc_record.type}: ${iocMatch.ioc_record.ioc}`;
      if (iocMatch.threat_level === 'critical') {
        iocScore = 25;
        reasons.push(`Matched CRITICAL IOC indicator in ${iocMatch.source} (+25)`);
      } else if (iocMatch.threat_level === 'high') {
        iocScore = 20;
        reasons.push(`Matched HIGH threat IOC indicator in ${iocMatch.source} (+20)`);
      } else {
        iocScore = 12;
        reasons.push(`Matched active IOC indicator in threat intelligence (+12)`);
      }
    }

    // 3. CVE correlation: 0–20
    let cveScore = 0;
    let cveMatchedStr: string | undefined = undefined;
    if (cveMatch.matched && cveMatch.cve_record) {
      cveMatchedStr = `${cveMatch.cve_record.cve_id} (CVSS ${cveMatch.cve_record.cvss_score})`;
      if (cveMatch.cve_record.cvss_score >= 9.0) {
        cveScore = 20;
        reasons.push(`Correlated with CRITICAL CVSS ${cveMatch.cve_record.cvss_score} (${cveMatch.cve_record.cve_id}) (+20)`);
      } else if (cveMatch.cve_record.cvss_score >= 7.0) {
        cveScore = 15;
        reasons.push(`Correlated with HIGH CVSS ${cveMatch.cve_record.cvss_score} (${cveMatch.cve_record.cve_id}) (+15)`);
      } else {
        cveScore = 10;
        reasons.push(`Correlated with relevant CVE vulnerability (+10)`);
      }
    }

    // 4. Asset criticality: 0–10
    let assetScore = 5; // default medium
    const asset = db.assets.find(a => a.hostname === event.hostname || a.ip_address === event.destination_ip);
    if (asset) {
      assetScore = Math.min(asset.criticality_score, 10);
      reasons.push(`Target asset ${asset.hostname} criticality score is ${assetScore}/10 (+${assetScore})`);
    } else {
      reasons.push(`Target endpoint has standard default tier (+5)`);
    }

    // 5. Behavior confidence: 0–5
    let confidenceScore = 3;
    if (confidencePct >= 95) {
      confidenceScore = 5;
    } else if (confidencePct >= 90) {
      confidenceScore = 4;
    } else if (confidencePct >= 80) {
      confidenceScore = 3;
    } else {
      confidenceScore = 2;
    }
    reasons.push(`Detection rule confidence is ${confidencePct}% (+${confidenceScore})`);

    // Sum and cap at 100
    const rawTotal = attackScore + iocScore + cveScore + assetScore + confidenceScore;
    const totalScore = Math.min(rawTotal, 100);

    // Determine severity
    let severity: SeverityLevel = 'LOW';
    if (totalScore >= 80) {
      severity = 'CRITICAL';
    } else if (totalScore >= 60) {
      severity = 'HIGH';
    } else if (totalScore >= 30) {
      severity = 'MEDIUM';
    } else {
      severity = 'LOW';
    }

    return {
      attack_score: attackScore,
      attack_type: attackType,
      ioc_score: iocScore,
      ioc_matched: iocMatchedStr,
      cve_score: cveScore,
      cve_matched: cveMatchedStr,
      asset_score: assetScore,
      asset_hostname: event.hostname,
      confidence_score: confidenceScore,
      confidence_pct: confidencePct,
      total_score: totalScore,
      severity,
      reasons
    };
  }
}

export const scoringEngine = new ScoringEngine();
