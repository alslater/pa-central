"""Pydantic v2 schemas for API request/response."""
from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import MAX_PASSWORD_BYTES
from app.models import (
    AlertKind,
    AlertSeverity,
    CredentialType,
    DaemonStatus,
    Ecosystem,
    RepoScanStatus,
    ScanStatus,
    ScanTrigger,
    SettingValueType,
    UserRole,
)

# ── Shared ────────────────────────────────────────────────────────────────────

class OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def _reject_password_over_bcrypt_limit(value: str | None) -> str | None:
    """Shared by every schema field that carries a password bcrypt will
    hash or check (login, set, reset — not TOTP codes or tokens).

    bcrypt hashes only the first 72 *bytes* of its input and (since bcrypt
    4.1) raises ValueError rather than truncating past that — reproduced
    directly: a 100-character password on POST /auth/login reached
    bcrypt.checkpw() unvalidated and crashed the request with an unhandled
    500. A plain `Field(max_length=72)` would count Python characters, not
    UTF-8 bytes, and so would still let through ordinary-looking non-ASCII
    input that exceeds the real limit (40 "é" characters, well under 72, is
    80 bytes). core.security also enforces this independently at the
    encoding boundary (hash_password/verify_password), since
    OAuth2PasswordRequestForm — used by the form-based POST /auth/token — is
    not a Pydantic model this schema layer can validate; the two checks
    exist for different reasons; this one turns the failure into a clean 422
    instead of a 500, and that one is what stops it reaching bcrypt at all
    for callers this file cannot reach.
    """
    if value is not None and len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes when UTF-8 encoded"
        )
    return value


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

    _validate_password = field_validator("password")(_reject_password_over_bcrypt_limit)


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
    """New user, created by an admin.

    `password` is optional because it is only meaningful when self-service
    reset is off. With it on, the user is emailed a welcome link and sets
    their own password, and supplying one here is rejected rather than
    silently ignored — see api/auth.py's register().
    """
    email: EmailStr
    display_name: str
    password: str | None = Field(default=None, min_length=12)
    role: UserRole = UserRole.viewer

    _validate_password = field_validator("password")(_reject_password_over_bcrypt_limit)


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12)

    _validate_password = field_validator("password")(_reject_password_over_bcrypt_limit)


class UserOut(OrmBase):
    id: int
    email: str
    display_name: str
    role: UserRole
    is_active: bool
    totp_enabled: bool
    created_at: datetime


class SelfPasswordChangeOut(UserOut):
    """PATCH /users/{id}'s own response when the caller changed their own
    password — UserOut plus a replacement access token.

    set_password bumps token_epoch on every password change (see its own
    docstring: this is what makes a reset actually revoke sessions already
    issued). That is exactly right for an admin resetting *someone else's*
    password, but when the caller changes their *own*, it also invalidates
    the very bearer token that just authenticated this request — the next
    API call using it 401s, with nothing in a plain UserOut response
    telling the frontend that is coming. access_token is populated only for
    this caller==target case (api/users.py's update_user); every other
    PATCH still returns a plain UserOut, since only the self-change case
    invalidates the credential the caller is currently using.
    """
    access_token: str


class RegisterOut(UserOut):
    """POST /auth/register's own response — UserOut plus two independent
    facts about the welcome link, both None when self-service reset is off
    (no email or token is ever created — the admin supplied a password
    directly).

    `welcome_email_sent`: was the SMTP send itself confirmed. False does
    not distinguish a confirmed SMTP failure from an unconfirmed one
    (timeout, an ambiguous disconnect) — see send_reset_email's own
    docstring for why that distinction was deliberately given up: the
    account is created either way, and a human admin decides what to do
    next (check the inbox, or trigger a fresh reset) rather than the
    backend guessing from an inherently ambiguous signal.

    `welcome_link_still_valid`: is the token behind that email still the
    account's live one, independent of whether the send succeeded. A
    concurrent event can retire it before or after a genuinely successful
    send — most commonly, self-service reset (or its SMTP configuration)
    being disabled while the send was in flight, which sweeps every
    outstanding token system-wide (see api/system_settings.py's
    turning_off/losing_smtp sweep) without touching whether *this*
    request's own email happened to go out. `welcome_email_sent=True` and
    `welcome_link_still_valid=False` together mean exactly that: the email
    was delivered, and the link inside it is already dead — a state the
    admin needs to know about even though the account itself survives and
    nothing here is destructive (see register()'s own docstring).
    """
    welcome_email_sent: bool | None = None
    welcome_link_still_valid: bool | None = None


class PasswordResetOut(BaseModel):
    """Result of an admin-initiated password reset.

    Which field is populated depends on the self_service_password_reset
    setting: with it off, a password is generated here and returned once for
    the admin to relay out-of-band (it is never stored in plaintext); with it
    on, a reset link is emailed to the user instead and no credential passes
    through the admin at all.
    """
    password: str | None = None
    reset_link_sent: bool = False


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12)

    _validate_password = field_validator("new_password")(_reject_password_over_bcrypt_limit)


class PasswordResetConfigOut(BaseModel):
    """Public — tells the login page whether to offer "Forgot password?"."""
    self_service_enabled: bool


# ── API Key ───────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: str


class ApiKeyOut(OrmBase):
    id: int
    name: str
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime
    owner_display_name: str = ''

    @classmethod
    def from_orm_with_owner(cls, key: object, owner_display_name: str) -> ApiKeyOut:
        instance = cls.model_validate(key, from_attributes=True)
        return instance.model_copy(update={'owner_display_name': owner_display_name})


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
    risks: list[dict] | None = None
    # See RepoScanResultIngest.risk_failures for why negative counts are rejected.
    risk_failures: int = Field(0, ge=0)
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
    risks: list[dict] | None
    risk_failures: int
    sources: list[str] | None
    scanned_at: datetime
    received_at: datetime


# ── Config Template ────────────────────────────────────────────────────────────

def _normalize_line_endings(v: str) -> str:
    """CRLF/lone-CR in stored TOML makes the frontend editor (CodeMirror,
    which always normalizes to \\n internally) treat the very first load of
    that content as an external edit and mark the page dirty before the
    user has touched anything. Normalizing at the write boundary means
    every template saved through this API is LF-only from here on."""
    return v.replace("\r\n", "\n").replace("\r", "\n")


class ConfigTemplateCreate(BaseModel):
    name: str
    description: str | None = None
    toml_content: str

    @field_validator("toml_content")
    @classmethod
    def normalize_toml_line_endings(cls, v: str) -> str:
        return _normalize_line_endings(v)


class ConfigTemplateUpdate(BaseModel):
    description: str | None = None
    toml_content: str | None = None
    is_default: bool | None = None

    @field_validator("toml_content")
    @classmethod
    def normalize_toml_line_endings(cls, v: str | None) -> str | None:
        return _normalize_line_endings(v) if v is not None else v


class ConfigTemplateOut(OrmBase):
    id: int
    name: str
    description: str | None
    toml_content: str
    is_default: bool
    created_by_id: int | None
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
    created_by_id: int | None
    created_at: datetime


# ── Dashboard summary ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_hosts: int
    hosts_online: int
    hosts_offline: int
    unacknowledged_alerts: int
    critical_alerts: int
    outstanding_scans_by_severity: dict[str, int] | None
    recent_alerts: list[AlertOut]


class ExposurePoint(BaseModel):
    date: date
    exposure: int


class ExposureHistoryOut(BaseModel):
    points: list[ExposurePoint]
    window_days: int


# ── System Settings ───────────────────────────────────────────────────────────

class SystemSettingOut(OrmBase):
    key: str
    value: str | None  # secret values are redacted to None in responses
    value_type: SettingValueType
    updated_at: datetime | None  # None for a synthesized default row (is_default=True) never actually saved
    updated_by_id: int | None
    # True when this key has no row in system_settings and `value` is the
    # runtime default the application falls back to (get_global_sla, etc.),
    # not a value an admin has ever saved. Lets the UI show what's actually
    # in effect without it looking like a persisted choice.
    is_default: bool = False


class SystemSettingPatch(BaseModel):
    """Dict of {key: new_value} pairs to upsert."""
    updates: dict[str, str | None]


class PasswordResetReadinessOut(BaseModel):
    """Whether self-service password reset can actually be enabled right
    now, and why not if it can't.

    Mirrors the exact checks patch_settings() enforces when enabling the
    feature and self_service_reset_enabled() enforces at read time — the
    same shared validators (looks_like_public_url, parse_smtp_port,
    parse_smtp_tls_mode, parse_smtp_from_addr), applied to the currently
    stored values rather than a submitted PATCH body. Exists because
    SystemSettings.tsx previously re-derived its own "is this ready"
    guess from only smtp_host/app_base_url being non-empty, which agreed
    with neither gate: a malformed base URL, an out-of-range port, an
    unrecognised TLS mode, or a From address containing CR/LF all made
    the toggle appear enableable while the backend would 400 the PATCH or
    /password-reset-config would report the feature unavailable anyway.
    """
    ready: bool
    reasons: list[str]


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
    notify_recipients: list[EmailStr] | None = None
    config_template_id: int | None = None
    is_enabled: bool = True
    scan_flags: str | None = Field(None, max_length=4096)
    subfolder: str | None = None
    sla_high_days: int | None = Field(None, gt=0)
    sla_medium_days: int | None = Field(None, gt=0)

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
    notify_recipients: list[EmailStr] | None = None
    config_template_id: int | None = None
    is_enabled: bool | None = None
    scan_flags: str | None = Field(None, max_length=4096)
    subfolder: str | None = None
    sla_high_days: int | None = Field(None, gt=0)
    sla_medium_days: int | None = Field(None, gt=0)

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
    created_by_id: int | None
    created_at: datetime
    updated_at: datetime
    sla_high_days: int | None
    sla_medium_days: int | None
    breach: bool
    breach_count: int
    scan_config_hash: str | None


class RepoScanHeadlineOut(BaseModel):
    id: int
    name: str
    url: str
    latest_status: RepoScanStatus | None
    latest_scanned_at: datetime | None
    open_findings_by_severity: dict[str, int]
    open_risks_by_level: dict[str, int]
    breach: bool
    breach_count: int


class RepoScanResultOut(OrmBase):
    id: int
    repo_scan_id: int
    status: RepoScanStatus
    pa_version: str | None
    finding_count: int
    findings: list[dict] | None
    risks: list[dict] | None
    risk_failures: int
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
    # Current open-breach state for the scan (not the state at the time of this result).
    scan_breach: bool
    scan_breach_count: int


class RepoScanResultIngest(BaseModel):
    """Posted by scan task to report outcome."""
    repo_scan_result_id: int
    status: RepoScanStatus
    pa_version: str | None = None
    finding_count: int = 0
    findings: list[dict] | None = None
    risks: list[dict] | None = None
    # A negative value is truthy in Python, so `if not result.risk_failures`
    # (risk_lifecycle.update_risk_records) would treat it as "scoring failed"
    # and skip closing absent risks, while the frontend's `> 0` check would
    # simultaneously hide the warning that explains why — stale risks with no
    # visible reason. Rejecting negative counts at ingestion closes that gap.
    risk_failures: int = Field(0, ge=0)
    sources: list[str] | None = None
    error_message: str | None = None


# ── Finding Record ─────────────────────────────────────────────────────────────

class FindingRecordOut(OrmBase):
    id: int
    repo_scan_id: int
    advisory_id: str
    package: str
    ecosystem: str
    severity: str
    first_found_at: datetime
    closed_at: datetime | None
    closed_reason: str | None = None
    reopen_count: int
    accepted_by_id: int | None
    accepted_at: datetime | None
    accepted_reason: str | None
    accepted_until: date | None
    # Detail fields (captured at first appearance)
    summary: str | None = None
    details: str | None = None
    package_version: str | None = None
    fixed_versions: str | None = None
    url: str | None = None
    is_malicious: bool | None = None
    # Computed — must be set by the API layer before returning
    is_accepted: bool
    days_open: int
    sla_days: int | None
    in_breach: bool
    scan_name: str | None = None


class PaginatedFindingsOut(BaseModel):
    items: list[FindingRecordOut]
    total: int
    page: int
    page_size: int


class FindingAcceptBody(BaseModel):
    reason: str = Field(..., max_length=1000)
    accepted_until: date | None = None

    @field_validator('reason')
    @classmethod
    def reason_must_not_be_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError('reason must not be blank')
        return stripped

    @field_validator('accepted_until')
    @classmethod
    def accepted_until_must_be_future(cls, v: date | None) -> date | None:
        if v is not None and v <= datetime.now(UTC).date():
            raise ValueError('accepted_until must be a future date')
        return v


# ── Risk Record ─────────────────────────────────────────────────────────────

class RiskRecordOut(OrmBase):
    id: int
    repo_scan_id: int
    package: str
    ecosystem: str
    package_version: str | None
    score: int
    level: str
    signals: list[dict]
    first_found_at: datetime
    closed_at: datetime | None
    closed_reason: str | None = None
    reopen_count: int
    accepted_by_id: int | None
    accepted_at: datetime | None
    accepted_reason: str | None
    accepted_until: date | None
    is_accepted: bool
    days_open: int
    scan_name: str | None = None


class PaginatedRisksOut(BaseModel):
    items: list[RiskRecordOut]
    total: int
    page: int
    page_size: int


class RiskAcceptBody(BaseModel):
    reason: str = Field(..., max_length=1000)
    accepted_until: date | None = None

    @field_validator("reason")
    @classmethod
    def reason_must_not_be_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("reason must not be blank")
        return stripped

    @field_validator("accepted_until")
    @classmethod
    def must_be_future(cls, v: date | None) -> date | None:
        if v is not None and v <= datetime.now(UTC).date():
            raise ValueError("accepted_until must be a future date")
        return v
