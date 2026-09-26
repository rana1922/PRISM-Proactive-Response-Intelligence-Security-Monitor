from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class SecurityEventSchema(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source: str = "web_server"
    source_ip: str
    destination_ip: str = "10.0.1.25"
    destination_port: Optional[int] = 443
    hostname: str = "web-prod-01"
    username: Optional[str] = "admin"
    event_type: str = "http_request"
    protocol: str = "HTTP"
    method: Optional[str] = "GET"
    url: Optional[str] = None
    user_agent: Optional[str] = "Mozilla/5.0"
    payload: Optional[str] = None
    process_name: Optional[str] = None
    process_command: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None

class DetectionResultSchema(BaseModel):
    attack_type: str
    confidence: int
    rule_id: str
    rule_name: str
    matched_patterns: List[str]
    description: str

class ScoreFactorsSchema(BaseModel):
    attack_score: int
    attack_type: str
    ioc_score: int
    ioc_matched: Optional[str] = None
    cve_score: int
    cve_matched: Optional[str] = None
    asset_score: int
    asset_hostname: Optional[str] = None
    confidence_score: int
    confidence_pct: int
    total_score: int
    severity: str
    reasons: List[str]

class AlertSchema(BaseModel):
    alert_id: str
    timestamp: datetime
    event_id: str
    attack_type: str
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    hostname: str
    username: Optional[str] = None
    url: Optional[str] = None
    payload: Optional[str] = None
    ioc_match: bool
    ioc_details: Optional[Dict[str, Any]] = None
    cve_match: bool
    cve_details: Optional[Dict[str, Any]] = None
    threat_score: int
    severity: str
    score_factors: ScoreFactorsSchema
    status: str
    recommended_actions: List[str]
    executed_actions: List[str]
    response_mode: str
    incident_id: Optional[str] = None

class IncidentSchema(BaseModel):
    incident_id: str
    alert_id: str
    title: str
    timestamp: datetime
    severity: str
    threat_score: int
    status: str
    source_ip: str
    hostname: str
    attack_type: str
    summary: str
    assigned_to: str
    actions_taken: List[str]
    why_detected: List[str]

class IOCSchema(BaseModel):
    ioc: str
    type: str
    threat_level: str
    source: str
    confidence: int
    last_seen: Optional[datetime] = None
    tags: List[str] = []
    description: str

class CVESchema(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_product: str
    published_date: str
    source_type: str = "DEMO"
    reference_url: Optional[str] = None

class ResponseAuditSchema(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    action: str
    target: str
    reason: str
    threat_score: int
    mode: str
    result: str
    details: Optional[Dict[str, Any]] = None

class DashboardSummarySchema(BaseModel):
    total_events: int
    active_threats: int
    critical_alerts: int
    blocked_ips: int
    open_incidents: int
    average_threat_score: int
    response_mode: str
    system_status: str
