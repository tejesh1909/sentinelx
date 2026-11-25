import uuid, datetime as dt
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .core import Base, now
def uid(): return str(uuid.uuid4())
class TS:
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now, onupdate=now)
S = lambda n=255, **k: mapped_column(String(n), **k)

class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True); name: Mapped[str] = S(32, unique=True)
class User(Base, TS):
    __tablename__ = "users"
    id: Mapped[str] = S(36, primary_key=True, default=uid)
    email: Mapped[str] = S(255, unique=True, index=True); full_name: Mapped[str] = S(120)
    password_hash: Mapped[str] = S(255); role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = S(64, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    role: Mapped[Role] = relationship(lazy="joined")
class AuthSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = S(32, primary_key=True); user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False); created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class Event(Base, TS):
    __tablename__ = "security_events"
    id: Mapped[str] = S(36, primary_key=True, default=uid)
    event_id: Mapped[str | None] = S(128, nullable=True)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = S(32, index=True); event_type: Mapped[str] = S(64, index=True)
    ip: Mapped[str | None] = S(45, nullable=True, index=True); user_identity: Mapped[str | None] = S(128, nullable=True, index=True)
    resource: Mapped[str | None] = S(512, nullable=True); action: Mapped[str | None] = S(64, nullable=True)
    status: Mapped[str] = S(32); severity: Mapped[str] = S(16, index=True)
    raw: Mapped[dict] = mapped_column(JSON); fingerprint: Mapped[str] = S(64, unique=True)
class Rule(Base, TS):
    __tablename__ = "detection_rules"
    id: Mapped[int] = mapped_column(primary_key=True); key: Mapped[str] = S(64, unique=True)
    name: Mapped[str] = S(120); description: Mapped[str] = S(400)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True); params: Mapped[dict] = mapped_column(JSON)
class Incident(Base, TS):
    __tablename__ = "incidents"
    id: Mapped[str] = S(36, primary_key=True, default=uid); title: Mapped[str] = S(300)
    status: Mapped[str] = S(20, default="new", index=True); priority: Mapped[str] = S(16, default="medium")
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0); risk_level: Mapped[str] = S(16, default="low")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True); correlation_key: Mapped[str | None] = S(300, nullable=True, index=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
class Threat(Base, TS):
    __tablename__ = "detected_threats"
    id: Mapped[str] = S(36, primary_key=True, default=uid); category: Mapped[str] = S(120, index=True)
    description: Mapped[str] = mapped_column(Text); event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), index=True)
    severity: Mapped[str] = S(16, index=True); confidence: Mapped[float] = mapped_column(Float)
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    user_identity: Mapped[str | None] = S(128, nullable=True); resource: Mapped[str | None] = S(512, nullable=True)
    ip: Mapped[str | None] = S(45, nullable=True); rule_key: Mapped[str] = S(64)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), primary_key=True)
class IncidentNote(Base):
    __tablename__ = "incident_notes"
    id: Mapped[int] = mapped_column(primary_key=True); incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    kind: Mapped[str] = S(20)  # note|status|assignment|priority|remediation|system
    body: Mapped[str] = mapped_column(Text); created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    threat_id: Mapped[str | None] = mapped_column(ForeignKey("detected_threats.id"), nullable=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    score: Mapped[int] = mapped_column(Integer); level: Mapped[str] = S(16)
    factors: Mapped[list] = mapped_column(JSON); explanation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class Integration(Base, TS):
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(primary_key=True); name: Mapped[str] = S(120); kind: Mapped[str] = S(40)
    status: Mapped[str] = S(20); simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = S(400); last_sync: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True); user_id: Mapped[str | None] = S(36, nullable=True)
    action: Mapped[str] = S(64); target: Mapped[str | None] = S(128, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True); ip: Mapped[str | None] = S(45, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now, index=True)
