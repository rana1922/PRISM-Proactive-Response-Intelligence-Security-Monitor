import {
  AlertRecord,
  DashboardSummary,
  IncidentRecord,
  IOCRecord,
  CVERecord,
  ResponseAuditRecord,
  SecurityEvent,
  DetectionRule
} from '../types';

const BASE_URL = '';

export interface PipelineSimulationResponse {
  event: SecurityEvent;
  is_attack: boolean;
  alert?: AlertRecord;
  incident?: IncidentRecord;
  explainable_breakdown?: {
    factors: { factor: string; score: number; detail: string }[];
    total: number;
    severity: string;
  };
  simulation_trace: {
    step: number;
    title: string;
    status: 'COMPLETED' | 'TRIGGERED' | 'BYPASSED';
    output: string;
  }[];
}

export const api = {
  async getHealth(): Promise<{ status: string; database: string; threat_intelligence: string; response_engine: string; version: string }> {
    const res = await fetch(`${BASE_URL}/api/health`);
    return res.json();
  },

  async getSummary(): Promise<DashboardSummary> {
    const res = await fetch(`${BASE_URL}/api/dashboard/summary`);
    return res.json();
  },

  async getEvents(limit = 50, search = ''): Promise<SecurityEvent[]> {
    const params = new URLSearchParams({ limit: limit.toString(), search });
    const res = await fetch(`${BASE_URL}/api/events?${params}`);
    return res.json();
  },

  async ingestEvent(event: Partial<SecurityEvent>): Promise<PipelineSimulationResponse> {
    const res = await fetch(`${BASE_URL}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    });
    return res.json();
  },

  async getAlerts(severity = 'ALL', status = 'ALL', limit = 100): Promise<AlertRecord[]> {
    const params = new URLSearchParams({ severity, status, limit: limit.toString() });
    const res = await fetch(`${BASE_URL}/api/alerts?${params}`);
    return res.json();
  },

  async getAlertDetail(alertId: string): Promise<AlertRecord> {
    const res = await fetch(`${BASE_URL}/api/alerts/${alertId}`);
    return res.json();
  },

  async resolveAlert(alertId: string): Promise<{ message: string; alert: AlertRecord }> {
    const res = await fetch(`${BASE_URL}/api/alerts/${alertId}/resolve`, { method: 'POST' });
    return res.json();
  },

  async markFalsePositive(alertId: string): Promise<{ message: string; alert: AlertRecord }> {
    const res = await fetch(`${BASE_URL}/api/alerts/${alertId}/false-positive`, { method: 'POST' });
    return res.json();
  },

  async getIncidents(status = 'ALL'): Promise<IncidentRecord[]> {
    const params = new URLSearchParams({ status });
    const res = await fetch(`${BASE_URL}/api/incidents?${params}`);
    return res.json();
  },

  async getIncidentDetail(incidentId: string): Promise<{ incident: IncidentRecord; related_alert?: AlertRecord }> {
    const res = await fetch(`${BASE_URL}/api/incidents/${incidentId}`);
    return res.json();
  },

  async getIOCs(): Promise<IOCRecord[]> {
    const res = await fetch(`${BASE_URL}/api/iocs`);
    return res.json();
  },

  async createIOC(data: Partial<IOCRecord>): Promise<IOCRecord> {
    const res = await fetch(`${BASE_URL}/api/iocs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return res.json();
  },

  async getCVEs(): Promise<CVERecord[]> {
    const res = await fetch(`${BASE_URL}/api/cves`);
    return res.json();
  },

  async syncCVEs(): Promise<{ synced_count: number; new_cves: CVERecord[]; message: string }> {
    const res = await fetch(`${BASE_URL}/api/cves/sync`, { method: 'POST' });
    return res.json();
  },

  async getAuditLog(): Promise<ResponseAuditRecord[]> {
    const res = await fetch(`${BASE_URL}/api/responses/audit`);
    return res.json();
  },

  async blockIP(ip: string, reason?: string): Promise<{ message: string; audit: ResponseAuditRecord }> {
    const res = await fetch(`${BASE_URL}/api/responses/block-ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    return res.json();
  },

  async isolateHost(hostname: string, reason?: string): Promise<{ message: string; audit: ResponseAuditRecord }> {
    const res = await fetch(`${BASE_URL}/api/responses/isolate-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname, reason })
    });
    return res.json();
  },

  // Attack simulator
  async simulateAttack(
    type: 'sql-injection' | 'rce' | 'malware' | 'brute-force' | 'port-scan',
    customPayload?: { source_ip?: string; hostname?: string; payload?: string }
  ): Promise<PipelineSimulationResponse> {
    const res = await fetch(`${BASE_URL}/api/simulator/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(customPayload || {})
    });
    return res.json();
  },

  async toggleDemo(): Promise<{ is_demo_active: boolean }> {
    const res = await fetch(`${BASE_URL}/api/simulator/toggle-demo`, { method: 'POST' });
    return res.json();
  },

  async getRules(): Promise<DetectionRule[]> {
    const res = await fetch(`${BASE_URL}/api/rules`);
    return res.json();
  },

  async toggleRule(ruleId: string): Promise<{ message: string; rule: DetectionRule }> {
    const res = await fetch(`${BASE_URL}/api/rules/${ruleId}/toggle`, { method: 'POST' });
    return res.json();
  },

  // Stats
  async getAttackStats(): Promise<{ name: string; raw_type: string; value: number }[]> {
    const res = await fetch(`${BASE_URL}/api/stats/attacks`);
    return res.json();
  },

  async getSeverityStats(): Promise<{ severity: string; count: number; fill: string }[]> {
    const res = await fetch(`${BASE_URL}/api/stats/severity`);
    return res.json();
  },

  async getTimelineStats(): Promise<{ time: string; events: number; critical: number }[]> {
    const res = await fetch(`${BASE_URL}/api/stats/timeline`);
    return res.json();
  },

  async getTopIps(): Promise<{
    ip_address: string;
    attack_count: number;
    highest_score: number;
    last_seen: string;
    threat_level: string;
    is_blocked: boolean;
    attack_types: string[];
  }[]> {
    const res = await fetch(`${BASE_URL}/api/stats/top-ips`);
    return res.json();
  }
};
