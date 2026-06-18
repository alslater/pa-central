"""Repo scan configuration CRUD and trigger."""
from typing import Annotated
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings as app_settings
from app.core.aws import EcsClient
from app.core.valkey import acquire_lock, get_valkey, release_lock
from app.models import RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger, RepoCredential, CredentialType, User, utcnow
from app.schemas import RepoScanCreate, RepoScanUpdate, RepoScanOut, RepoScanResultOut, RepoScanResultWithName
from app.api.deps import require_operator, require_admin, require_viewer

router = APIRouter(prefix="/repo-scans", tags=["repo-scans"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
OperatorDep = Annotated[User, Depends(require_operator)]
AdminDep = Annotated[User, Depends(require_admin)]


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
    return result.scalars().all()


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
        created_by_id=user.id,
    )
    db.add(scan)
    await db.commit()
    return scan


ViewerDep = Annotated[User, Depends(require_viewer)]

@router.get("/results")
async def list_all_results(db: DbDep, _: ViewerDep, limit: int = 100) -> list[RepoScanResultWithName]:
    rows = await db.execute(
        select(RepoScanResult, RepoScan.name, RepoScan.url)
        .join(RepoScan, RepoScan.id == RepoScanResult.repo_scan_id)
        .order_by(RepoScanResult.started_at.desc())
        .limit(limit)
    )
    out = []
    for result, scan_name, scan_url in rows.all():
        d = {c.key: getattr(result, c.key) for c in RepoScanResult.__table__.columns}
        d["scan_name"] = scan_name
        d["scan_url"] = scan_url
        out.append(RepoScanResultWithName.model_validate(d))
    return out


@router.get("/{scan_id}")
async def get_repo_scan(scan_id: int, db: DbDep, _: OperatorDep) -> RepoScanOut:
    scan = await db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Repo scan not found")
    return scan


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
    scan.updated_at = utcnow()
    await db.commit()
    return scan


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
        "PA_EXTRA_ARGS": scan.extra_args or "",
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
