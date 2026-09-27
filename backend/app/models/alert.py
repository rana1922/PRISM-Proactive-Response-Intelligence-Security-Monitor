from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, JSON, Index
try:
    from app.models.event import Base
except ImportError:
    from backend.app.models.event import Base

class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_id = Column(String(64), nullable=False)
    attack_type = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    destination_port = Column(Integer, nullable=True)
    hostname = Column(String(128), nullable=False)
    username = Column(String(64), nullable=True)
    url = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    
    ioc_match = Column(Boolean, default=False)
    ioc_details = Column(JSON, nullable=True)
    
    cve_match = Column(Boolean, default=False)
    cve_details = Column(JSON, nullable=True)
    
    threat_score = Column(Integer, nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    score_factors = Column(JSON, nullable=False)
    status = Column(String(32), default="NEW", nullable=False, index=True)
    
    recommended_actions = Column(JSON, nullable=False)
    executed_actions = Column(JSON, nullable=False)
    response_mode = Column(String(32), default="SIMULATION", nullable=False)
    incident_id = Column(String(64), nullable=True, index=True)

    __table_args__ = (
        Index("ix_alerts_severity_score", "severity", "threat_score"),
    )


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), unique=True, nullable=False, index=True)
    alert_id = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    threat_score = Column(Integer, nullable=False)
    status = Column(String(32), default="NEW", nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    hostname = Column(String(128), nullable=False)
    attack_type = Column(String(64), nullable=False)
    summary = Column(Text, nullable=False)
    assigned_to = Column(String(128), nullable=False)
    actions_taken = Column(JSON, nullable=False)
    why_detected = Column(JSON, nullable=False)


class IOCModel(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc = Column(String(255), unique=True, nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)
    threat_level = Column(String(32), nullable=False)
    source = Column(String(128), nullable=False)
    confidence = Column(Integer, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    tags = Column(JSON, nullable=False)
    description = Column(Text, nullable=False)


class CVEModel(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    cvss_score = Column(Integer, nullable=False)  # stored as float or rounded
    severity = Column(String(32), nullable=False)
    affected_product = Column(String(255), nullable=False)
    published_date = Column(String(64), nullable=False)
    source_type = Column(String(32), default="DEMO", nullable=False)
    reference_url = Column(String(255), nullable=True)


class ResponseAuditModel(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False, index=True)
    target = Column(String(128), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    threat_score = Column(Integer, nullable=False)
    mode = Column(String(32), default="SIMULATION", nullable=False)
    result = Column(String(32), default="SUCCESS", nullable=False)
    details = Column(JSON, nullable=True)


class AssetModel(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(128), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    asset_type = Column(String(64), nullable=False)
    criticality = Column(String(32), nullable=False)
    criticality_score = Column(Integer, nullable=False)
    owner = Column(String(128), nullable=False)
    location = Column(String(128), nullable=False)


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    attack_type = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    confidence = Column(Integer, nullable=False)
