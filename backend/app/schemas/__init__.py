"""Pydantic v2 schemas for API request/response."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal  # noqa — used by field_validator

from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator

from app.models import UserRole, DaemonStatus, AlertSeverity, AlertKind, ScanStatus, Ecosystem, SettingValueType, CredentialType, RepoScanStatus, ScanTrigger


# ── Shared ────────────────────────────────────────────────────────────────────

class OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TotpChallengeResponse(BaseModel):
    totp_required: bool = True
    totp_setup_required: bool = False
    totp_session_token: str
    totp_uri: str | None = None


class TotpVerifyRequest(BaseModel):
    totp_session_token: str
    code: str


class TotpSetupResponse(BaseModel):
    totp_uri: str


class TotpConfirmRequest(BaseModel):
    code: str


class TotpDisableRequest(BaseModel):
    code: str


# ── User ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    display_name: str
    password: str = Field(min_length=12)
    role: UserRole = UserRole.viewer


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12)


class UserOut(OrmBase):
    id: int
    email: str
    display_name: str
    role: UserRole
    is_active: bool
    totp_enabled: bool
    created_at: datetime


# ── API Key ───────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: str


class ApiKeyOut(OrmBase):
    id: int
    name: str
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    """Returned once only — includes the raw key."""
    raw_key: str


# ── Host ──────────────────────────────────────────────────────────────────────

class HostCreate(BaseModel):
    name: str
    description: str | None = None
    hostname: str | None = None
    tags: list[str] = []


class HostUpdate(BaseModel):
    description: str | None = None
    hostname: str | None = None
    tags: list[str] | None = None


class HostOut(OrmBase):
    id: int
    owner_user_id: int
    name: str
    description: str | None
    hostname: str | None
    tags: list[str] | None
    pa_version: str | None
    daemon_status: DaemonStatus
    daemon_uptime_seconds: int | None
    last_seen_at: datetime | None
    created_at: datetime


# ── Host Heartbeat (uploaded by pa agent) ─────────────────────────────────────

class HeartbeatPayload(BaseModel):
    hostname: str
    pa_version: str | None = None
    daemon_status: DaemonStatus = DaemonStatus.running
    daemon_uptime_seconds: int | None = None


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertPayload(BaseModel):
    """Uploaded by pa agent.

    Severity is normalised to lowercase on ingestion so package-alert's
    uppercase OSV values ("CRITICAL", "HIGH", …) are accepted alongside
    the heuristic level "warning".
    """
    hostname: str
    package_name: str
    package_version: str | None = None
    ecosystem: Ecosystem = Ecosystem.pypi
    kind: AlertKind = AlertKind.osv
    severity: AlertSeverity = AlertSeverity.medium
    advisory_id: str | None = None
    summary: str | None = None
    project_path: str | None = None
    risk_score: int | None = None
    signals: list[dict] | None = None  # [{name, score, reason}] from heuristic alerts
    occurred_at: datetime | None = None
    raw: dict | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class AlertOut(OrmBase):
    id: int
    host_id: int
    package_name: str
    package_version: str | None
    ecosystem: Ecosystem
    kind: AlertKind
    severity: AlertSeverity
    advisory_id: str | None
    summary: str | None
    project_path: str | None
    risk_score: int | None
    signals: list[dict] | None
    acknowledged: bool
    occurred_at: datetime
    received_at: datetime


class AlertAcknowledge(BaseModel):
    acknowledged: bool = True


class AlertBulkAcknowledge(BaseModel):
    alert_ids: list[int]
    acknowledged: bool = True


# ── Scan ──────────────────────────────────────────────────────────────────────

class ScanPayload(BaseModel):
    """Uploaded by pa agent (output of pa scan-project --format json).

    Accepts both `project_path` and `root` (package-alert's JSON key) for
    the project directory field.
    """
    model_config = ConfigDict(populate_by_name=True)

    hostname: str
    project_path: str = Field(alias="root", default=None)
    scan_type: str = "project"
    status: ScanStatus
    finding_count: int = 0
    findings: list[dict] | None = None
    sources: list[str] | None = None
    unpinned: list[dict] | None = None  # packages without pinned versions
    scanned_at: datetime | None = None
    raw: dict | None = None

    @field_validator("project_path", mode="before")
    @classmethod
    def require_project_path(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("project_path (or root) is required")
        return v


class ScanOut(OrmBase):
    id: int
    host_id: int
    project_path: str
    scan_type: str
    status: ScanStatus
    finding_count: int
    findings: list[dict] | None
    sources: list[str] | None
    scanned_at: datetime
    received_at: datetime


# ── Config Template ────────────────────────────────────────────────────────────

class ConfigTemplateCreate(BaseModel):
    name: str
    description: str | None = None
    toml_content: str


class ConfigTemplateUpdate(BaseModel):
    description: str | None = None
    toml_content: str | None = None
    is_default: bool | None = None


class ConfigTemplateOut(OrmBase):
    id: int
    name: str
    description: str | None
    toml_content: str
    is_default: bool
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class ConfigAssignOut(OrmBase):
    id: int
    host_id: int
    template_id: int
    assigned_at: datetime


# ── Config template lint ──────────────────────────────────────────────────────

class LintResult(BaseModel):
    valid: bool
    errors: list[str]
    warnings: list[str]


class ValidateRequest(BaseModel):
    toml_content: str


# ── Scan options ──────────────────────────────────────────────────────────────

class ScanFlag(BaseModel):
    name: str
    cli_flag: str
    help: str
    type: Literal["bool", "str"]


class ScanOptions(BaseModel):
    flags: list[ScanFlag]
    exclusions: list[list[str]]


# ── Cooldown ──────────────────────────────────────────────────────────────────

class CooldownCreate(BaseModel):
    package_name: str
    package_version: str | None = None
    ecosystem: Ecosystem = Ecosystem.pypi
    host_id: int | None = None  # None = fleet-wide
    note: str | None = None
    expires_at: datetime | None = None


class CooldownOut(OrmBase):
    id: int
    package_name: str
    package_version: str | None
    ecosystem: Ecosystem
    host_id: int | None
    note: str | None
    expires_at: datetime | None
    created_by_id: int
    created_at: datetime


# ── Dashboard summary ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_hosts: int
    hosts_online: int
    hosts_offline: int
    unacknowledged_alerts: int
    critical_alerts: int
    scans_with_findings: int
    recent_alerts: list[AlertOut]


# ── System Settings ───────────────────────────────────────────────────────────

class SystemSettingOut(OrmBase):
    key: str
    value: str | None  # secret values are redacted to None in responses
    value_type: SettingValueType
    updated_at: datetime
    updated_by_id: int | None


class SystemSettingPatch(BaseModel):
    """Dict of {key: new_value} pairs to upsert."""
    updates: dict[str, str | None]


# ── Repo Scan ─────────────────────────────────────────────────────────────────

class RepoCredentialCreate(BaseModel):
    name: str
    credential_type: CredentialType
    credential_value: str | None = None
    ssh_key_passphrase: str | None = None


class RepoCredentialUpdate(BaseModel):
    name: str | None = None
    credential_type: CredentialType | None = None
    credential_value: str | None = None
    ssh_key_passphrase: str | None = None


class RepoCredentialOut(OrmBase):
    id: int
    name: str
    credential_type: CredentialType
    created_at: datetime
    updated_at: datetime


def _validate_subfolder(v: str | None) -> str | None:
    if v is None:
        return v
    v = v.strip()
    if not v or v == ".":
        return None
    if len(v) > 500:
        raise ValueError("subfolder must be 500 characters or fewer")
    if "\\" in v:
        raise ValueError("subfolder must use forward slashes")
    from pathlib import PurePosixPath
    p = PurePosixPath(v)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("subfolder must be a relative path with no .. segments")
    return v


class RepoScanCreate(BaseModel):
    name: str
    url: str
    branch: str = "main"
    credential_id: int | None = None
    cron_schedule: str | None = None
    cron_timezone: str | None = None
    min_notify_severity: AlertSeverity = AlertSeverity.medium
    notify_recipients: list[str] | None = None
    config_template_id: int | None = None
    is_enabled: bool = True
    scan_flags: str | None = Field(None, max_length=4096)
    subfolder: str | None = None

    @field_validator("subfolder")
    @classmethod
    def subfolder_not_absolute(cls, v: str | None) -> str | None:
        return _validate_subfolder(v)


class RepoScanUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    branch: str | None = None
    credential_id: int | None = None
    cron_schedule: str | None = None
    cron_timezone: str | None = None
    min_notify_severity: AlertSeverity | None = None
    notify_recipients: list[str] | None = None
    config_template_id: int | None = None
    is_enabled: bool | None = None
    scan_flags: str | None = Field(None, max_length=4096)
    subfolder: str | None = None

    @field_validator("subfolder")
    @classmethod
    def subfolder_not_absolute(cls, v: str | None) -> str | None:
        return _validate_subfolder(v)


class RepoScanOut(OrmBase):
    id: int
    name: str
    url: str
    branch: str
    credential_id: int | None
    cron_schedule: str | None
    cron_timezone: str | None
    pa_version: str | None
    scan_flags: str | None
    subfolder: str | None
    min_notify_severity: AlertSeverity
    notify_recipients: list[str] | None
    config_template_id: int | None
    is_enabled: bool
    last_scan_at: datetime | None
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class RepoScanResultOut(OrmBase):
    id: int
    repo_scan_id: int
    status: RepoScanStatus
    pa_version: str | None
    finding_count: int
    findings: list[dict] | None
    sources: list[str] | None
    error_message: str | None
    triggered_by: ScanTrigger
    ecs_task_arn: str | None
    started_at: datetime
    completed_at: datetime | None
    notified: bool


class RepoScanResultWithName(RepoScanResultOut):
    scan_name: str
    scan_url: str


class RepoScanResultIngest(BaseModel):
    """Posted by scan task to report outcome."""
    repo_scan_result_id: int
    status: RepoScanStatus
    pa_version: str | None = None
    finding_count: int = 0
    findings: list[dict] | None = None
    sources: list[str] | None = None
    error_message: str | None = None
