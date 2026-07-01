"""
All ORM models in one file for simplicity.
Import each symbol from here or import the module.
"""
from __future__ import annotations

import enum
from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean, Date, DateTime, Enum, ForeignKey, Index, Integer, String, Text, JSON
)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UtcDateTime(TypeDecorator):
    """Stores datetimes as UTC in SQLite (which has no native TZ support).

    On write: converts any tz-aware datetime to UTC, strips tzinfo.
    On read: returns a tz-aware UTC datetime.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: Optional[datetime], dialect: Any) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value: Optional[datetime], dialect: Any) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


# ── Enums ────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    admin = "admin"
    operator = "operator"
    developer = "developer"
    viewer = "viewer"


class DaemonStatus(str, enum.Enum):
    running = "running"
    stopped = "stopped"
    unknown = "unknown"


class AlertSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    warning = "warning"   # package-alert heuristic level alias
    low = "low"
    info = "info"


class AlertKind(str, enum.Enum):
    osv = "osv"
    heuristic = "heuristic"


class ScanStatus(str, enum.Enum):
    clean = "clean"
    findings = "findings"
    error = "error"


class Ecosystem(str, enum.Enum):
    pypi = "pypi"
    npm = "npm"
    packagist = "packagist"
    other = "other"


class SettingValueType(str, enum.Enum):
    string = "string"
    int = "int"
    bool = "bool"
    json = "json"
    secret = "secret"


class CredentialType(str, enum.Enum):
    none = "none"
    ssh_key = "ssh_key"
    https_token = "https_token"


class RepoScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    success = "success"
    failed = "failed"


class ScanTrigger(str, enum.Enum):
    scheduled = "scheduled"
    manual = "manual"


# ── User ─────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.viewer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    api_keys: Mapped[list[ApiKey]] = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")


# ── API Key ───────────────────────────────────────────────────────────────────

class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    user: Mapped[User] = relationship("User", back_populates="api_keys")


# ── Host ──────────────────────────────────────────────────────────────────────

class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Unique within a user's namespace: (owner_user_id, name)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, default=list)
    pa_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    daemon_status: Mapped[DaemonStatus] = mapped_column(Enum(DaemonStatus), default=DaemonStatus.unknown)
    daemon_uptime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    owner: Mapped[User] = relationship("User")
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="host", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="host", cascade="all, delete-orphan")
    config_assignments: Mapped[list[ConfigAssignment]] = relationship("ConfigAssignment", back_populates="host", cascade="all, delete-orphan")
    cooldown_entries: Mapped[list[CooldownEntry]] = relationship("CooldownEntry", back_populates="host", cascade="all, delete-orphan")


# ── Alert ─────────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    package_name: Mapped[str] = mapped_column(String(200), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(Enum(Ecosystem), default=Ecosystem.pypi)
    kind: Mapped[AlertKind] = mapped_column(Enum(AlertKind), default=AlertKind.osv)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity), default=AlertSeverity.medium)
    advisory_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)      # heuristic alerts
    signals: Mapped[list | None] = mapped_column(JSON, nullable=True)           # [{name, score, reason}]
    project_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # full pa JSON payload
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    host: Mapped[Host] = relationship("Host", back_populates="alerts")


# ── Scan ──────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    project_path: Mapped[str] = mapped_column(String(500), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="project")  # project | installed | cache
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.clean)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list | None] = mapped_column(JSON, nullable=True)  # list of finding dicts
    sources: Mapped[list | None] = mapped_column(JSON, nullable=True)  # e.g. ["Python (requirements.txt)", "Node.js (package-lock.json)"]
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    host: Mapped[Host] = relationship("Host", back_populates="scans")


# ── Config Template ────────────────────────────────────────────────────────────

class ConfigTemplate(Base):
    __tablename__ = "config_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    toml_content: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow, onupdate=utcnow)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    assignments: Mapped[list[ConfigAssignment]] = relationship("ConfigAssignment", back_populates="template")


class ConfigAssignment(Base):
    """Maps a config template to a host."""
    __tablename__ = "config_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    template_id: Mapped[int] = mapped_column(ForeignKey("config_templates.id"), nullable=False)
    assigned_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    host: Mapped[Host] = relationship("Host", back_populates="config_assignments")
    template: Mapped[ConfigTemplate] = relationship("ConfigTemplate", back_populates="assignments")


# ── Cooldown Entry ─────────────────────────────────────────────────────────────

class CooldownEntry(Base):
    """Fleet-wide or host-specific cooldown allowlist entries."""
    __tablename__ = "cooldown_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_name: Mapped[str] = mapped_column(String(200), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(Enum(Ecosystem), default=Ecosystem.pypi)
    # If host_id is NULL, this is a fleet-wide entry
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)

    host: Mapped[Host | None] = relationship("Host", back_populates="cooldown_entries")


# ── System Setting ────────────────────────────────────────────────────────────

class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    value_type: Mapped[SettingValueType] = mapped_column(
        Enum(SettingValueType), default=SettingValueType.string, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow, onupdate=utcnow)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


# ── Repo Credential ───────────────────────────────────────────────────────────

class RepoCredential(Base):
    __tablename__ = "repo_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    credential_type: Mapped[CredentialType] = mapped_column(Enum(CredentialType), nullable=False)
    credential_secret_arn: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow, onupdate=utcnow)

    scans: Mapped[list["RepoScan"]] = relationship("RepoScan", back_populates="credential")


# ── Repo Scan ─────────────────────────────────────────────────────────────────

class RepoScan(Base):
    __tablename__ = "repo_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    branch: Mapped[str] = mapped_column(String(200), default="main", nullable=False)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("repo_credentials.id"), nullable=True)
    cron_schedule: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cron_timezone: Mapped[str | None] = mapped_column(String(100), nullable=True)
    pa_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    scan_flags: Mapped[str | None] = mapped_column(Text, nullable=True)
    subfolder: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scan_config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    min_notify_severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), default=AlertSeverity.medium, nullable=False
    )
    notify_recipients: Mapped[list | None] = mapped_column(JSON, nullable=True)
    config_template_id: Mapped[int | None] = mapped_column(ForeignKey("config_templates.id"), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sla_high_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sla_medium_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow, onupdate=utcnow)

    credential: Mapped["RepoCredential | None"] = relationship("RepoCredential", back_populates="scans")
    config_template: Mapped[ConfigTemplate | None] = relationship("ConfigTemplate")
    results: Mapped[list[RepoScanResult]] = relationship(
        "RepoScanResult", back_populates="repo_scan", cascade="all, delete-orphan"
    )


class RepoScanResult(Base):
    __tablename__ = "repo_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_scan_id: Mapped[int] = mapped_column(ForeignKey("repo_scans.id"), nullable=False)
    status: Mapped[RepoScanStatus] = mapped_column(
        Enum(RepoScanStatus), default=RepoScanStatus.pending, nullable=False
    )
    pa_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    sources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[ScanTrigger] = mapped_column(
        Enum(ScanTrigger), default=ScanTrigger.manual, nullable=False
    )
    ecs_task_arn: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    repo_scan: Mapped[RepoScan] = relationship("RepoScan", back_populates="results")


# ── Finding Record ────────────────────────────────────────────────────────────

class FindingRecord(Base):
    __tablename__ = "finding_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_scan_id: Mapped[int] = mapped_column(
        ForeignKey("repo_scans.id", ondelete="CASCADE"), nullable=False
    )

    # Identity key — three columns; not unique (episodes repeat)
    advisory_id: Mapped[str] = mapped_column(String(200), nullable=False)
    package: Mapped[str] = mapped_column(String(200), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(100), nullable=False)

    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), nullable=False
    )

    # Detail fields captured at first appearance
    summary: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    package_version: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    fixed_versions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_malicious: Mapped[Optional[bool]] = mapped_column(Boolean(), nullable=True)

    first_found_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    closed_at: Mapped[Optional[datetime]] = mapped_column(UtcDateTime(), nullable=True)
    closed_reason: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    reopen_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Acceptance
    accepted_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    accepted_at: Mapped[Optional[datetime]] = mapped_column(UtcDateTime(), nullable=True)
    accepted_reason: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    accepted_until: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)

    __table_args__ = (
        Index("ix_finding_records_identity", "repo_scan_id", "advisory_id", "package", "ecosystem"),
        Index("ix_finding_records_closed_at", "closed_at"),
    )
