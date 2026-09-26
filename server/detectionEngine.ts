import { SecurityEvent, DetectionResult } from './types';
import { db } from './db';

export class DetectionEngine {
  // SQL Injection patterns
  private sqlPatterns = [
    /'\s*OR\s*['"]?1['"]?\s*=\s*['"]?1/i,
    /UNION\s+SELECT/i,
    /SELECT\s+\*\s+FROM/i,
    /DROP\s+TABLE/i,
    /INSERT\s+INTO/i,
    /information_schema/i,
    /--\s*$/,
    /xp_cmdshell/i,
    /OR\s+1\s*=\s*1/i,
    /WAITFOR\s+DELAY/i,
    /SLEEP\s*\(\d+\)/i,
    /BENCHMARK\s*\(/i
  ];

  // RCE patterns
  private rcePatterns = [
    /cmd\.exe/i,
    /powershell(\.exe)?\s+(-enc|-c|iex)/i,
    /\/bin\/bash/i,
    /\/bin\/sh/i,
    /\bwget\b/i,
    /\bcurl\b/i,
    /\bnc\s+(-e|-l|-p|\d+)/i,
    /python\s+-c/i,
    /bash\s+-c/i,
    /whoami/i,
    /cat\s+\/etc\/passwd/i,
    /rm\s+-rf/i,
    /;\s*(ls|id|uname|pwd)/i
  ];

  // Malware keywords
  private malwareKeywords = [
    'mimikatz',
    'cobaltstrike',
    'covenant',
    'wannacry',
    'trickbot',
    'redline',
    'meterpreter',
    'beacon.exe',
    'payload.sh'
  ];

  // State trackers for Brute Force & Port Scan correlation
  private authFailures: Map<string, { count: number; lastTime: number }> = new Map();
  private portScanHistory: Map<string, { ports: Set<number>; lastTime: number }> = new Map();

  public analyzeEvent(event: SecurityEvent): DetectionResult | null {
    const rawSearchTarget = [
      event.url || '',
      event.payload || '',
      event.process_command || '',
      event.process_name || '',
      event.user_agent || '',
      event.domain || ''
    ].join(' ');

    // 1. Check SQL Injection Rule
    const sqlRule = db.detectionRules.find(r => r.rule_id === 'PRISM-SQL-001' && r.enabled);
    if (sqlRule) {
      const matched = this.sqlPatterns.filter(pattern => pattern.test(rawSearchTarget));
      if (matched.length > 0) {
        return {
          attack_type: 'SQL_INJECTION',
          confidence: Math.min(90 + matched.length * 2, 98),
          rule_id: sqlRule.rule_id,
          rule_name: sqlRule.name,
          matched_patterns: matched.map(p => p.toString()),
          description: `SQL Injection syntax detected matching pattern ${matched[0].toString()}`
        };
      }
    }

    // 2. Check RCE Rule
    const rceRule = db.detectionRules.find(r => r.rule_id === 'PRISM-RCE-001' && r.enabled);
    if (rceRule) {
      const matched = this.rcePatterns.filter(pattern => pattern.test(rawSearchTarget));
      if (matched.length > 0) {
        return {
          attack_type: 'RCE',
          confidence: Math.min(92 + matched.length * 2, 98),
          rule_id: rceRule.rule_id,
          rule_name: rceRule.name,
          matched_patterns: matched.map(p => p.toString()),
          description: `Remote command execution invocation detected: ${matched[0].toString()}`
        };
      }
    }

    // 3. Check Malware Detection
    const malRule = db.detectionRules.find(r => r.rule_id === 'PRISM-MAL-001' && r.enabled);
    if (malRule) {
      // Check file hash against known malicious hashes in IOC database
      if (event.file_hash) {
        const hashMatch = db.iocs.find(i => i.type === 'HASH' && i.ioc.toLowerCase() === event.file_hash?.toLowerCase());
        if (hashMatch) {
          return {
            attack_type: 'MALWARE',
            confidence: hashMatch.confidence,
            rule_id: malRule.rule_id,
            rule_name: malRule.name,
            matched_patterns: [`Known malicious hash: ${event.file_hash}`],
            description: `Known malicious file signature identified: ${hashMatch.description}`
          };
        }
      }

      // Check keywords
      const matchedKw = this.malwareKeywords.filter(kw => rawSearchTarget.toLowerCase().includes(kw));
      if (matchedKw.length > 0) {
        return {
          attack_type: 'MALWARE',
          confidence: 94,
          rule_id: malRule.rule_id,
          rule_name: malRule.name,
          matched_patterns: matchedKw,
          description: `Trojan/Malware activity detected referencing suspicious payload ${matchedKw[0]}`
        };
      }
    }

    // 4. Check Brute Force
    const bfRule = db.detectionRules.find(r => r.rule_id === 'PRISM-BF-001' && r.enabled);
    if (bfRule && (event.event_type === 'auth_event' || (event.url && event.url.includes('/login')))) {
      const now = Date.now();
      const ip = event.source_ip;
      const history = this.authFailures.get(ip) || { count: 0, lastTime: now };
      
      // Reset if outside 5 minute window
      if (now - history.lastTime > 300000) {
        history.count = 1;
      } else {
        history.count += 1;
      }
      history.lastTime = now;
      this.authFailures.set(ip, history);

      if (history.count >= 3 || (event.payload && event.payload.includes('admin:'))) {
        return {
          attack_type: 'BRUTE_FORCE',
          confidence: Math.min(85 + history.count * 2, 95),
          rule_id: bfRule.rule_id,
          rule_name: bfRule.name,
          matched_patterns: [`Multiple auth attempts (${history.count}) from IP ${ip}`],
          description: `Repeated failed authentication attempts detected from source ${ip}`
        };
      }
    }

    // 5. Check Port Scan
    const scanRule = db.detectionRules.find(r => r.rule_id === 'PRISM-SCAN-001' && r.enabled);
    if (scanRule && (event.event_type === 'network_event' || event.destination_port)) {
      const ip = event.source_ip;
      const now = Date.now();
      const entry = this.portScanHistory.get(ip) || { ports: new Set<number>(), lastTime: now };
      
      if (event.destination_port) {
        entry.ports.add(event.destination_port);
      }
      entry.lastTime = now;
      this.portScanHistory.set(ip, entry);

      if (entry.ports.size >= 3 || (event.payload && event.payload.includes('SYN probe'))) {
        return {
          attack_type: 'PORT_SCAN',
          confidence: Math.min(80 + entry.ports.size * 3, 94),
          rule_id: scanRule.rule_id,
          rule_name: scanRule.name,
          matched_patterns: [`Multiple probed destination ports: ${Array.from(entry.ports).join(', ')}`],
          description: `Port scanning reconnaissance detected probing multiple endpoints`
        };
      }
    }

    return null;
  }
}

export const detectionEngine = new DetectionEngine();
