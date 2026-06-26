"""Repo scan configuration CRUD and trigger."""
from datetime import datetime, timedelta, timezone
from typing import Annotated
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings as app_settings
from app.core.aws import EcsClient
from app.core.valkey import acquire_lock, get_valkey, release_lock
from app.models import AlertSeverity, FindingRecord, RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger, RepoCredential, CredentialType, User, utcnow
from app.schemas import FindingRecordOut, RepoScanCreate, RepoScanUpdate, RepoScanOut, RepoScanResultOut, RepoScanResultWithName
from app.api.deps import require_operator, require_admin, require_viewer
from app.services.finding_lifecycle import (
    build_finding_out, compute_scan_config_hash, compute_sla_days,
    get_effective_sla, get_global_sla, not_accepted_sql_expr,
)

router = APIRouter(prefix="/repo-scans", tags=["repo-scans"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
OperatorDep = Annotated[User, Depends(require_operator)]
AdminDep = Annotated[User, Depends(require_admin)]


_SLA_SEVERITIES = [AlertSeverity.critical, AlertSeverity.high, AlertSeverity.medium]


async def _get_global_sla_for_repo(db: AsyncSession) -> tuple[int, int]:
    high, medium, _ = await get_global_sla(db)
    return high, medium


def _breach_candidates_stmt(scan_ids: list[int], now: datetime, min_sla: int | None = None):
    """SELECT (repo_scan_id, severity, first_found_at) for open, non-accepted findings
    that can possibly be in breach.

    Filters applied in SQL before Python evaluation:
    - Only severities that have an SLA (critical/high/medium).
    - Accepted findings excluded (accepted_at IS NULL or accepted_until expired).
    - Optionally, only findings old enough to breach the minimum effective SLA
      across the scans being evaluated. Callers must supply the minimum of all
      *effective* (post-override) SLAs — not the global minimum — because the
      minimum effective SLA is the safe lower bound regardless of whether
      overrides are stricter or looser than the global default.
    """
    stmt = (
        select(
            FindingRecord.repo_scan_id,
            FindingRecord.severity,
            FindingRecord.first_found_at,
        )
        .where(FindingRecord.repo_scan_id.in_(scan_ids))
        .where(FindingRecord.closed_at.is_(None))
        .where(FindingRecord.severity.in_(_SLA_SEVERITIES))
        .where(not_accepted_sql_expr())
    )
    if min_sla is not None:
        # Breach is defined as age.days > sla_days, so a finding found exactly
        # min_sla days ago cannot be in breach. Use min_sla + 1 to align the
        # SQL cutoff with the Python predicate and avoid fetching boundary rows.
        stmt = stmt.where(FindingRecord.first_found_at <= now - timedelta(days=min_sla + 1))
    return stmt


def _age_in_breach(first_found_at: datetime, sla_days: int | None, now: datetime) -> bool:
    """True if the finding's age exceeds its SLA. Closed/accepted filtering is done in SQL."""
    if sla_days is None:
        return False
    return (now - first_found_at).days > sla_days


async def _breach_info(db: AsyncSession, scan: RepoScan, global_high: int, global_medium: int) -> tuple[bool, int]:
    """Return (has_breach, breach_count) for a single repo scan."""
    eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium)
    now = datetime.now(timezone.utc)
    rows = await db.execute(_breach_candidates_stmt([scan.id], now, min_sla=min(eff_high, eff_medium)))
    count = sum(
        1 for _, severity, first_found_at in rows
        if _age_in_breach(first_found_at, compute_sla_days(severity, eff_high, eff_medium), now)
    )
    return count > 0, count



def _repo_scan_out(scan: RepoScan, has_breach: bool, breach_count: int) -> RepoScanOut:
    """Build a RepoScanOut, injecting the computed breach fields."""
    return RepoScanOut.model_validate({
        **{c.key: getattr(scan, c.key) for c in RepoScan.__table__.columns},
        "breach": has_breach,
        "breach_count": breach_count,
    })


@asynccontextmanager
async def _get_valkey():
    if app_settings.valkey_url:
        r = get_valkey(app_settings.valkey_url)
        try:
            yield r
        finally:
            await r.aclose()
    else:
        yield None


@router.get("")
async def list_repo_scans(db: DbDep, _: OperatorDep) -> list[RepoScanOut]:
    result = await db.execute(select(RepoScan).order_by(RepoScan.name))
    scans = result.scalars().all()
    if not scans:
        return []

    global_high, global_medium = await _get_global_sla_for_repo(db)
    scan_ids = [s.id for s in scans]
    now = datetime.now(timezone.utc)

    # Compute the minimum effective SLA across all scans — this is the safe
    # lower-bound cutoff regardless of whether overrides are stricter or looser.
    eff_slas = [get_effective_sla(s, global_high, global_medium) for s in scans]
    min_sla = min(v for h, m in eff_slas for v in (h, m)) if eff_slas else min(global_high, global_medium)

    # Fetch breach candidates for all scans in one query, then group in Python.
    open_rows = await db.execute(_breach_candidates_stmt(scan_ids, now, min_sla=min_sla))
    # Each row is (repo_scan_id, severity, first_found_at) — lightweight tuples, not ORM objects.
    candidates_by_scan: dict[int, list[tuple[AlertSeverity, datetime]]] = {sid: [] for sid in scan_ids}
    for scan_id, severity, first_found_at in open_rows:
        candidates_by_scan[scan_id].append((severity, first_found_at))

    out = []
    for scan in scans:
        eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium)
        count = sum(
            1 for severity, first_found_at in candidates_by_scan[scan.id]
            if _age_in_breach(first_found_at, compute_sla_days(severity, eff_high, eff_medium), now)
        )
        out.append(_repo_scan_out(scan, count > 0, count))
    return out


@router.post("", status_code=201)
async def create_repo_scan(body: RepoScanCreate, db: DbDep, user: OperatorDep) -> RepoScanOut:
    if body.credential_id is not None:
        if not await db.get(RepoCredential, body.credential_id):
            raise HTTPException(404, "Credential not found")
    scan = RepoScan(
        name=body.name, url=body.url, branch=body.branch,
        credential_id=body.credential_id,
        cron_schedule=body.cron_schedule,
        cron_timezone=body.cron_timezone,
        min_notify_severity=body.min_notify_severity,
        notify_recipients=body.notify_recipients,
        config_template_id=body.config_template_id,
        is_enabled=body.is_enabled,
        scan_flags=body.scan_flags,
        subfolder=body.subfolder,
        scan_config_hash=compute_scan_config_hash(body.scan_flags, body.subfolder, body.config_template_id),
        sla_high_days=body.sla_high_days,
        sla_medium_days=body.sla_medium_days,
        created_by_id=user.id,
    )
    db.add(scan)
    await db.commit()
    return _repo_scan_out(scan, False, 0)


ViewerDep = Annotated[User, Depends(require_viewer)]

@router.get("/results")
async def list_all_results(db: DbDep, _: ViewerDep, limit: int = 100) -> list[RepoScanResultWithName]:
    rows = await db.execute(
        select(
            RepoScanResult,
            RepoScan.name,
            RepoScan.url,
            RepoScan.id,
            RepoScan.sla_high_days,
            RepoScan.sla_medium_days,
        )
        .join(RepoScan, RepoScan.id == RepoScanResult.repo_scan_id)
        .order_by(RepoScanResult.started_at.desc())
        .limit(limit)
    )
    global_high, global_medium = await _get_global_sla_for_repo(db)
    result_rows = rows.all()

    # Collect scan metadata for the distinct scan_ids present in this result page.
    scan_meta: dict[int, tuple[str, str, int, int]] = {}  # scan_id -> (name, url, eff_high, eff_medium)
    for _, scan_name, scan_url, scan_id, sla_high, sla_medium in result_rows:
        if scan_id not in scan_meta:
            eff_high = sla_high if sla_high is not None else global_high
            eff_medium = sla_medium if sla_medium is not None else global_medium
            scan_meta[scan_id] = (scan_name, scan_url, eff_high, eff_medium)

    # Fetch breach candidates for those scan_ids in one query, then count in Python.
    now = datetime.now(timezone.utc)
    candidates_by_scan: dict[int, list[tuple[AlertSeverity, datetime]]] = {sid: [] for sid in scan_meta}
    if scan_meta:
        min_sla = min(v for _, _, h, m in scan_meta.values() for v in (h, m))
        open_rows = await db.execute(
            _breach_candidates_stmt(list(scan_meta), now, min_sla=min_sla)
        )
        for scan_id, severity, first_found_at in open_rows:
            candidates_by_scan[scan_id].append((severity, first_found_at))

    breach_cache: dict[int, tuple[bool, int]] = {}
    for scan_id, (_, _, eff_high, eff_medium) in scan_meta.items():
        count = sum(
            1 for severity, first_found_at in candidates_by_scan[scan_id]
            if _age_in_breach(first_found_at, compute_sla_days(severity, eff_high, eff_medium), now)
        )
        breach_cache[scan_id] = (count > 0, count)

    out = []
    for result, _, _, scan_id, _, _ in result_rows:
        scan_name, scan_url, _, _ = scan_meta[scan_id]
        has_breach, breach_count = breach_cache[scan_id]
        d = {c.key: getattr(result, c.key) for c in RepoScanResult.__table__.columns}
        d["scan_name"] = scan_name
        d["scan_url"] = scan_url
        d["scan_breach"] = has_breach
        d["scan_breach_count"] = breach_count
        out.append(RepoScanResultWithName.model_validate(d))
    return out


@router.get("/{scan_id}")
async def get_repo_scan(scan_id: int, db: DbDep, _: OperatorDep) -> RepoScanOut:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    global_high, global_medium = await _get_global_sla_for_repo(db)
    has_breach, breach_count = await _breach_info(db, scan, global_high, global_medium)
    return _repo_scan_out(scan, has_breach, breach_count)


@router.patch("/{scan_id}")
async def update_repo_scan(scan_id: int, body: RepoScanUpdate, db: DbDep, _: OperatorDep) -> RepoScanOut:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    updates = body.model_dump(exclude_none=True)
    if "credential_id" in updates and updates["credential_id"] is not None:
        if not await db.get(RepoCredential, updates["credential_id"]):
            raise HTTPException(404, "Credential not found")
    for k, v in updates.items():
        setattr(scan, k, v)
    _CONFIG_FIELDS = {"scan_flags", "subfolder", "config_template_id"}
    if _CONFIG_FIELDS & set(updates):
        scan.scan_config_hash = compute_scan_config_hash(
            scan.scan_flags, scan.subfolder, scan.config_template_id
        )
    scan.updated_at = utcnow()
    await db.commit()
    global_high, global_medium = await _get_global_sla_for_repo(db)
    has_breach, breach_count = await _breach_info(db, scan, global_high, global_medium)
    return _repo_scan_out(scan, has_breach, breach_count)


@router.delete("/{scan_id}", status_code=204)
async def delete_repo_scan(scan_id: int, db: DbDep, _: AdminDep) -> None:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/results")
async def list_results(scan_id: int, db: DbDep, _: OperatorDep) -> list[RepoScanResultOut]:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    result = await db.execute(
        select(RepoScanResult)
        .where(RepoScanResult.repo_scan_id == scan_id)
        .order_by(RepoScanResult.started_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.get("/{scan_id}/findings", response_model=list[FindingRecordOut])
async def get_repo_scan_findings(scan_id: int, db: DbDep, _: AdminDep) -> list[FindingRecordOut]:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    global_high, global_medium = await _get_global_sla_for_repo(db)
    eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium)
    now = datetime.now(timezone.utc)
    rows = await db.execute(
        select(FindingRecord)
        .where(FindingRecord.repo_scan_id == scan_id)
        .where(FindingRecord.closed_at.is_(None))
        .order_by(
            case(
                (FindingRecord.severity == 'critical', 0),
                (FindingRecord.severity == 'high', 1),
                (FindingRecord.severity == 'medium', 2),
                (FindingRecord.severity == 'warning', 3),
                (FindingRecord.severity == 'low', 4),
                else_=5,
            ),
            FindingRecord.first_found_at,
        )
    )
    return [build_finding_out(r, eff_high, eff_medium, now) for r in rows.scalars().all()]


@router.post("/{scan_id}/trigger", status_code=202)
async def trigger_scan(scan_id: int, db: DbDep, user: OperatorDep) -> RepoScanResultOut:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    if not scan.is_enabled:
        raise HTTPException(400, "Repo scan is disabled")

    async with _get_valkey() as r:
        if r is not None:
            if not await acquire_lock(r, f"repo_scan:{scan_id}:lock", ttl_seconds=900):
                raise HTTPException(409, "Scan already in progress")

    # Resolve credential
    credential: RepoCredential | None = None
    if scan.credential_id:
        credential = await db.get(RepoCredential, scan.credential_id)

    cred_type = credential.credential_type if credential else CredentialType.none
    cred_arn = credential.credential_secret_arn if credential else None

    pa_version = ""
    config_toml = ""
    from app.models import SystemSetting, ConfigTemplate
    pa_version_row = await db.get(SystemSetting, "pa_version")
    if pa_version_row:
        pa_version = pa_version_row.value or ""
    if scan.config_template_id:
        tmpl = await db.get(ConfigTemplate, scan.config_template_id)
        if tmpl:
            config_toml = tmpl.toml_content

    result = RepoScanResult(
        repo_scan_id=scan.id,
        status=RepoScanStatus.pending,
        triggered_by=ScanTrigger.manual,
        pa_version=pa_version,
        scan_config_hash=scan.scan_config_hash,
    )
    db.add(result)
    await db.flush()

    local_arn = (cred_arn or "").startswith("local://")
    task_env = {
        "PA_VERSION": pa_version,
        "REPO_SCAN_RESULT_ID": str(result.id),
        "REPO_URL": scan.url,
        "BRANCH": scan.branch,
        "CREDENTIAL_TYPE": cred_type.value,
        "CREDENTIAL_SECRET_ARN": "" if local_arn else (cred_arn or ""),
        "CREDENTIAL_VALUE": cred_arn[len("local://"):] if local_arn else "",
        "FLEET_API_URL": app_settings.fleet_base_url,
        "FLEET_SYSTEM_API_KEY": app_settings.fleet_system_api_key or "",
        "PA_CONFIG_TOML": config_toml,
        "PA_SCAN_FLAGS": scan.scan_flags or "",
        "PA_SUBFOLDER": scan.subfolder or "",
    }
    try:
        if app_settings.local_docker_scan:
            from app.core.docker_runner import run_local_scan
            fleet_url = app_settings.scan_task_fleet_url or "http://host.docker.internal:8000"
            task_arn = await run_local_scan(app_settings.scan_task_image, task_env, fleet_url)
        else:
            ecs = EcsClient(region_name=app_settings.aws_region)
            subnet_ids = [s.strip() for s in app_settings.scan_task_subnet_ids.split(",") if s.strip()]
            sg_ids = [s.strip() for s in app_settings.scan_task_security_group_ids.split(",") if s.strip()]
            task_arn = await ecs.run_scan_task(
                cluster_arn=app_settings.ecs_cluster_arn or "",
                task_definition_arn=app_settings.scan_task_definition_arn or "",
                subnet_ids=subnet_ids,
                security_group_ids=sg_ids,
                environment=task_env,
            )
        result.status = RepoScanStatus.running
        result.ecs_task_arn = task_arn
    except Exception as exc:
        result.status = RepoScanStatus.failed
        result.error_message = f"{'Docker' if app_settings.local_docker_scan else 'ECS'} launch failed: {exc}"
        result.completed_at = utcnow()
        async with _get_valkey() as r:
            if r:
                await release_lock(r, f"repo_scan:{scan_id}:lock")

    await db.commit()
    await db.refresh(result)
    return result
