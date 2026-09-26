from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class SecurityEventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source = Column(String(64), nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    destination_port = Column(Integer, nullable=True)
    hostname = Column(String(128), nullable=False)
    username = Column(String(64), nullable=True)
    event_type = Column(String(64), nullable=False, index=True)
    protocol = Column(String(16), nullable=False)
    method = Column(String(16), nullable=True)
    url = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    process_name = Column(String(128), nullable=True)
    process_command = Column(Text, nullable=True)
    file_hash = Column(String(128), nullable=True)
    domain = Column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_events_source_ip_type", "source_ip", "event_type"),
    )
