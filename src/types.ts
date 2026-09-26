export type AttackType = 
  | 'SQL_INJECTION'
  | 'RCE'
  | 'MALWARE'
  | 'BRUTE_FORCE'
  | 'PORT_SCAN'
  | 'SUSPICIOUS_TRAFFIC'
  | 'BENIGN';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type ResponseActionType = 
  | 'BLOCK_IP'
  | 'ISOLATE_HOST'
  | 'DISABLE_USER'
  | 'KILL_PROCESS'
  | 'ESCALATE_SOC'
  | 'CREATE_INCIDENT';

export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source: string;
  source_ip: string;
  destination_ip: string;
  destination_port?: number;
  hostname: string;
  username?: string;
  event_type: 'http_request' | 'auth_event' | 'endpoint_event' | 'dns_event' | 'network_event' | 'process_event';
  protocol: 'HTTP' | 'HTTPS' | 'SSH' | 'TCP' | 'UDP' | 'DNS';
  method?: string;
  url?: string;
  user_agent?: string;
  payload?: string;
  process_name?: string;
  process_command?: string;
  file_hash?: string;
  domain?: string;
}

export interface DetectionResult {
  attack_type: AttackType;
  confidence: number;
  rule_id: string;
  rule_name: string;
  matched_patterns: string[];
  description: string;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  attack_type: AttackType;
  severity: SeverityLevel;
  enabled: boolean;
  confidence: number;
}

export interface IOCRecord {
  id: string;
  ioc: string;
  type: IOCType;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  confidence: number;
  last_seen: string;
  tags: string[];
  description: string;
}

export interface CVERecord {
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: SeverityLevel;
  affected_product: string;
  published_date: string;
  source_type: 'LIVE' | 'DEMO';
  reference_url?: string;
}

export interface AssetRecord {
  hostname: string;
  ip_address: string;
  asset_type: 'WEB_SERVER' | 'DATABASE' | 'AUTH_SERVER' | 'PAYMENT_GATEWAY' | 'WORKSTATION' | 'DNS_SERVER';
  criticality: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  criticality_score: number;
  owner: string;
  location: string;
}

export interface ScoreFactors {
  attack_score: number;
  attack_type: AttackType;
  ioc_score: number;
  ioc_matched?: string;
  cve_score: number;
  cve_matched?: string;
  asset_score: number;
  asset_hostname?: string;
  confidence_score: number;
  confidence_pct: number;
  total_score: number;
  severity: SeverityLevel;
  reasons: string[];
}

export interface AlertRecord {
  alert_id: string;
  timestamp: string;
  event_id: string;
  attack_type: AttackType;
  source_ip: string;
  destination_ip: string;
  destination_port?: number;
  hostname: string;
  username?: string;
  url?: string;
  payload?: string;
  ioc_match: boolean;
  ioc_details?: {
    ioc: string;
    type: IOCType;
    threat_level: string;
    source: string;
    confidence: number;
  };
  cve_match: boolean;
  cve_details?: {
    cve_id: string;
    cvss_score: number;
    severity: string;
    affected_product: string;
  };
  threat_score: number;
  severity: SeverityLevel;
  score_factors: ScoreFactors;
  status: AlertStatus;
  recommended_actions: ResponseActionType[];
  executed_actions: ResponseActionType[];
  response_mode: 'SIMULATION' | 'ENFORCE';
  incident_id?: string;
}

export interface IncidentRecord {
  incident_id: string;
  alert_id: string;
  title: string;
  timestamp: string;
  severity: SeverityLevel;
  threat_score: number;
  status: AlertStatus;
  source_ip: string;
  hostname: string;
  attack_type: AttackType;
  summary: string;
  assigned_to: string;
  actions_taken: ResponseActionType[];
  why_detected: string[];
}

export interface ResponseAuditRecord {
  id: string;
  timestamp: string;
  actor: 'PRISM-AUTO' | 'SOC-ANALYST' | 'ADMIN';
  action: ResponseActionType;
  target: string;
  reason: string;
  threat_score: number;
  mode: 'SIMULATION' | 'ENFORCE' | 'ACTIVE';
  result: 'SUCCESS' | 'FAILED';
  details?: Record<string, unknown>;
}

export interface DashboardSummary {
  total_events: number;
  active_threats: number;
  critical_alerts: number;
  blocked_ips: number;
  open_incidents: number;
  average_threat_score: number;
  response_mode: string;
  system_status: 'healthy' | 'degraded';
}
