"""
Agent ingest endpoints — called by the package-alert plugin running on each host.
All routes authenticate via X-API-Key. Hosts self-register on first heartbeat.
"""
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.alerts import broadcast_alert
from app.api.deps import get_api_key, require_system_key, resolve_host
from app.core.database import get_db
from app.models import (
    Alert,
    ConfigAssignment,
    ConfigTemplate,
    CooldownEntry,
    RepoScanResult,
    RepoScanStatus,
    Scan,
    utcnow,
)
from app.schemas import (
    AlertOut,
    AlertPayload,
    CooldownOut,
    HeartbeatPayload,
    RepoScanResultIngest,
    ScanOut,
    ScanPayload,
)
from app.services.finding_lifecycle import update_finding_records
from app.services.risk_lifecycle import update_risk_records

ApiKeyDep = Annotated[tuple, Depends(get_api_key)]
DbDep = Annotated[AsyncSession, Depends(get_db)]

router = APIRouter(prefix="/ingest", tags=["agent-ingest"])


@router.post("/heartbeat", status_code=204)
async def heartbeat(
    body: HeartbeatPayload,
    auth: ApiKeyDep,
    db: DbDep,
) -> None:
    """Called periodically by the agent to report daemon status and register itself."""
    key_obj, _ = auth
    host = await resolve_host(body.hostname, key_obj, db)
    host.last_seen_at = utcnow()
    host.daemon_status = body.daemon_status
    host.daemon_uptime_seconds = body.daemon_uptime_seconds
    if body.pa_version:
        host.pa_version = body.pa_version
    if not host.hostname:
        host.hostname = body.hostname
    await db.commit()


@router.post("/alerts", response_model=AlertOut, status_code=201)
async def ingest_alert(
    body: AlertPayload,
    auth: ApiKeyDep,
    db: DbDep,
) -> AlertOut:
    """Called when package-alert fires an alert on the host."""
    key_obj, _ = auth
    host = await resolve_host(body.hostname, key_obj, db)
    host.last_seen_at = utcnow()
    alert = Alert(
        host_id=host.id,
        package_name=body.package_name,
        package_version=body.package_version,
        ecosystem=body.ecosystem,
        kind=body.kind,
        severity=body.severity,
        advisory_id=body.advisory_id,
        summary=body.summary,
        project_path=body.project_path,
        risk_score=body.risk_score,
        signals=body.signals,
        occurred_at=body.occurred_at or utcnow(),
        raw=body.raw,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    try:
        broadcast_alert(AlertOut.model_validate(alert).model_dump(mode="json"))
    except Exception:  # noqa: BLE001 S110
        pass
    return alert


@router.post("/scans", response_model=ScanOut, status_code=201)
async def ingest_scan(
    body: ScanPayload,
    auth: ApiKeyDep,
    db: DbDep,
) -> ScanOut:
    """Called after pa scan-project completes on the host."""
    key_obj, _ = auth
    host = await resolve_host(body.hostname, key_obj, db)
    host.last_seen_at = utcnow()
    scan = Scan(
        host_id=host.id,
        project_path=body.project_path,
        scan_type=body.scan_type,
        status=body.status,
        finding_count=body.finding_count,
        findings=body.findings,
        risks=body.risks,
        risk_failures=body.risk_failures,
        sources=body.sources,
        scanned_at=body.scanned_at or utcnow(),
        raw=body.raw,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/config", response_class=PlainTextResponse)
async def get_assigned_config(
    hostname: Annotated[str, Query()],
    auth: ApiKeyDep,
    db: DbDep,
) -> PlainTextResponse:
    """
    Pull the TOML config assigned to this host.
    Returns 204 if no config is assigned.
    Pass ?hostname=<reported_hostname> to identify the host.
    """
    key_obj, _ = auth
    host = await resolve_host(hostname, key_obj, db)
    await db.commit()
    result = await db.execute(
        select(ConfigAssignment)
        .where(ConfigAssignment.host_id == host.id)
        .order_by(ConfigAssignment.assigned_at.desc())
        .limit(1)
    )
    assignment = result.scalar_one_or_none()
    if not assignment:
        return PlainTextResponse("", status_code=204)
    template = await db.get(ConfigTemplate, assignment.template_id)
    if not template:
        return PlainTextResponse("", status_code=204)
    return PlainTextResponse(template.toml_content, media_type="text/plain")


@router.get("/cooldown")
async def get_cooldown_entries(
    hostname: Annotated[str, Query()],
    auth: ApiKeyDep,
    db: DbDep,
) -> list[CooldownOut]:
    """
    Return active cooldown allowlist entries applicable to this host.
    Includes both host-specific entries and fleet-wide entries (host_id IS NULL).
    Expired entries (expires_at in the past) are excluded.
    """
    key_obj, _ = auth
    host = await resolve_host(hostname, key_obj, db)
    await db.commit()
    now = utcnow()
    result = await db.execute(
        select(CooldownEntry)
        .where(
            or_(CooldownEntry.host_id == host.id, CooldownEntry.host_id.is_(None)),
            or_(CooldownEntry.expires_at.is_(None), CooldownEntry.expires_at > now),
        )
        .order_by(CooldownEntry.package_name)
    )
    return result.scalars().all()


async def _send_result_email(result_id: int) -> None:
    """Background task: load result and dispatch appropriate email notification."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from app.core.config import settings as app_settings
    from app.core.db_config import async_connect_args, async_url
    from app.core.email import (
        EmailService,
        SmtpConfig,
        build_failure_email,
        build_findings_email,
        filter_findings_by_severity,
    )
    from app.core.encryption import decrypt_value
    from app.core.valkey import get_valkey
    from app.models import (
        RepoScan,
        RepoScanResult,
        RepoScanStatus,
        SettingValueType,
        SystemSetting,
        User,
        UserRole,
    )

    engine = create_async_engine(
        async_url(), pool_pre_ping=True, connect_args=async_connect_args()
    )
    try:
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            result = await session.get(RepoScanResult, result_id)
            if not result:
                return
            scan = await session.get(RepoScan, result.repo_scan_id)
            if not scan:
                return

            # Load SMTP config from system settings
            sm_result = await session.execute(select(SystemSetting))
            settings_map: dict[str, str] = {}
            for s in sm_result.scalars().all():
                if s.value is None:
                    settings_map[s.key] = ""
                elif s.value_type == SettingValueType.secret:
                    try:
                        settings_map[s.key] = decrypt_value(s.value, app_settings.settings_encryption_key)
                    except Exception:  # noqa: BLE001
                        settings_map[s.key] = ""
                else:
                    settings_map[s.key] = s.value

            smtp_host = settings_map.get("smtp_host")
            if not smtp_host:
                return  # SMTP not configured

            smtp_cfg = SmtpConfig(
                host=smtp_host,
                port=int(settings_map.get("smtp_port") or "587"),
                username=settings_map.get("smtp_username") or None,
                password=settings_map.get("smtp_password") or None,
                from_addr=settings_map.get("smtp_from", "pa-central@localhost"),
                tls_mode=settings_map.get("smtp_tls_mode", "starttls"),
            )
            svc = EmailService(smtp_cfg)

            admins = await session.execute(
                select(User).where(User.role == UserRole.admin, User.is_active.is_(True))
            )
            admin_emails = [u.email for u in admins.scalars().all()]
            if not admin_emails:
                return

            valkey = None
            if app_settings.valkey_url:
                valkey = get_valkey(app_settings.valkey_url)

            lock_key = f"repo_scan_result:{result_id}:notify"
            try:
                if result.status == RepoScanStatus.failed:
                    msg = build_failure_email(
                        repo_name=scan.name, repo_url=scan.url, branch=scan.branch,
                        pa_version=result.pa_version, error_message=result.error_message or "",
                        ecs_task_arn=result.ecs_task_arn,
                        recipients=admin_emails, from_addr=smtp_cfg.from_addr,
                    )
                    sent = await svc.send_with_dedup(msg, admin_emails, valkey, lock_key)
                else:
                    findings = result.findings or []
                    filtered = filter_findings_by_severity(findings, scan.min_notify_severity)
                    if not filtered:
                        return
                    all_recipients = list(set(admin_emails + (scan.notify_recipients or [])))
                    msg = build_findings_email(
                        repo_name=scan.name, branch=scan.branch, pa_version=result.pa_version or "",
                        findings=findings, min_severity=scan.min_notify_severity,
                        recipients=all_recipients, from_addr=smtp_cfg.from_addr,
                    )
                    sent = await svc.send_with_dedup(msg, all_recipients, valkey, lock_key)

                if sent:
                    result.notified = True
                    await session.commit()
            finally:
                if valkey:
                    await valkey.aclose()
    finally:
        await engine.dispose()


@router.post("/repo-scan-result", status_code=204)
async def ingest_repo_scan_result(
    body: RepoScanResultIngest,
    db: DbDep,
    background_tasks: BackgroundTasks,
    _: Annotated[None, Depends(require_system_key)],
) -> None:
    """Called by the ECS scan task to report its outcome."""
    from fastapi import HTTPException

    from app.core.config import settings as app_settings
    from app.core.valkey import get_valkey, release_lock

    result = await db.get(RepoScanResult, body.repo_scan_result_id)
    if not result:
        raise HTTPException(404, "Scan result not found")

    result.status = body.status
    result.pa_version = body.pa_version
    result.finding_count = body.finding_count
    result.findings = body.findings
    result.risks = body.risks
    result.risk_failures = body.risk_failures
    result.sources = body.sources
    result.error_message = body.error_message
    result.completed_at = utcnow()

    if body.status == RepoScanStatus.success:
        await update_finding_records(db, result)
        await update_risk_records(db, result)

    await db.commit()

    # Release Valkey lock so next trigger can proceed
    if app_settings.valkey_url:
        r = get_valkey(app_settings.valkey_url)
        await release_lock(r, f"repo_scan:{result.repo_scan_id}:lock")
        await r.aclose()

    # Enqueue email notification
    needs_email = (
        body.status == RepoScanStatus.failed or
        (body.status.value == "success" and (body.finding_count or 0) > 0)
    )
    if needs_email:
        background_tasks.add_task(
            _send_result_email, result.id
        )
