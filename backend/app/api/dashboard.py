from datetime import timedelta
from types import SimpleNamespace

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.models import Alert, AlertSeverity, FindingRecord, Host, User, UserRole, utcnow
from app.schemas import AlertOut, DashboardStats, ExposureHistoryOut, ExposurePoint
from app.services.finding_lifecycle import (
    compute_exposure_history,
    get_global_sla,
    load_finding_acceptance_events,
    not_accepted_sql_expr,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardStats)
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DashboardStats:
    online_cutoff = utcnow() - timedelta(minutes=settings.host_online_threshold_minutes)

    # Developers see only their own hosts' stats; all other roles see fleet-wide.
    scoped = user.role == UserRole.developer
    owned_host_ids = (
        select(Host.id).where(Host.owner_user_id == user.id).scalar_subquery()
        if scoped else None
    )

    host_q = select(func.count()).select_from(Host)
    online_q = select(func.count()).select_from(Host).where(Host.last_seen_at >= online_cutoff)
    alert_q = select(func.count()).select_from(Alert).where(Alert.acknowledged.is_(False))
    critical_q = (
        select(func.count()).select_from(Alert)
        .where(Alert.severity == AlertSeverity.critical, Alert.acknowledged.is_(False))
    )
    recent_q = select(Alert).where(Alert.acknowledged.is_(False))

    if scoped:
        host_q = host_q.where(Host.id.in_(owned_host_ids))
        online_q = online_q.where(Host.id.in_(owned_host_ids))
        alert_q = alert_q.where(Alert.host_id.in_(owned_host_ids))
        critical_q = critical_q.where(Alert.host_id.in_(owned_host_ids))
        recent_q = recent_q.where(Alert.host_id.in_(owned_host_ids))

    total_hosts = (await db.execute(host_q)).scalar()
    hosts_online = (await db.execute(online_q)).scalar()
    unacknowledged = (await db.execute(alert_q)).scalar()
    critical = (await db.execute(critical_q)).scalar()
    recent_alerts = (
        await db.execute(recent_q.order_by(Alert.received_at.desc()).limit(10))
    ).scalars().all()

    outstanding_by_severity: dict[str, int] | None = None
    if user.role == UserRole.admin:
        outstanding_by_severity = {s.value: 0 for s in AlertSeverity}
        rows = await db.execute(
            select(FindingRecord.severity, func.count(func.distinct(FindingRecord.repo_scan_id)))
            .where(FindingRecord.closed_at.is_(None))
            .where(not_accepted_sql_expr(utcnow().date()))
            .group_by(FindingRecord.severity)
        )
        for severity, count in rows:
            outstanding_by_severity[severity.value] = count

    return DashboardStats(
        total_hosts=total_hosts or 0,
        hosts_online=hosts_online or 0,
        hosts_offline=(total_hosts or 0) - (hosts_online or 0),
        unacknowledged_alerts=unacknowledged or 0,
        critical_alerts=critical or 0,
        outstanding_findings_by_severity=outstanding_by_severity,
        recent_alerts=[AlertOut.model_validate(a) for a in recent_alerts],
    )


@router.get("/exposure-history", response_model=ExposureHistoryOut)
async def get_exposure_history(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
    days: int = Query(90, ge=1, le=3650),
) -> ExposureHistoryOut:
    _, _, retention_days = await get_global_sla(db)
    window_days = min(days, retention_days)
    today = utcnow().date()

    rows = await db.execute(
        select(FindingRecord.id, FindingRecord.severity, FindingRecord.first_found_at,
               FindingRecord.closed_at)
    )
    records = [
        SimpleNamespace(id=fid, severity=sev, first_found_at=ffa, closed_at=ca)
        for fid, sev, ffa, ca in rows
    ]
    events_by_record_id = await load_finding_acceptance_events(db, [r.id for r in records])

    history = compute_exposure_history(records, events_by_record_id, window_days, today)
    return ExposureHistoryOut(
        points=[ExposurePoint(date=d, exposure=e) for d, e in history],
        window_days=window_days,
    )
