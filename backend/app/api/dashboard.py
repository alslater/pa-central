from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models import Alert, AlertSeverity, Host, Scan, User, UserRole, utcnow
from app.schemas import AlertOut, DashboardStats

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
    scans_q = select(func.count()).select_from(Scan).where(Scan.finding_count > 0)
    recent_q = select(Alert).where(Alert.acknowledged.is_(False))

    if scoped:
        host_q = host_q.where(Host.id.in_(owned_host_ids))
        online_q = online_q.where(Host.id.in_(owned_host_ids))
        alert_q = alert_q.where(Alert.host_id.in_(owned_host_ids))
        critical_q = critical_q.where(Alert.host_id.in_(owned_host_ids))
        scans_q = scans_q.where(Scan.host_id.in_(owned_host_ids))
        recent_q = recent_q.where(Alert.host_id.in_(owned_host_ids))

    total_hosts = (await db.execute(host_q)).scalar()
    hosts_online = (await db.execute(online_q)).scalar()
    unacknowledged = (await db.execute(alert_q)).scalar()
    critical = (await db.execute(critical_q)).scalar()
    scans_with_findings = (await db.execute(scans_q)).scalar()
    recent_alerts = (
        await db.execute(recent_q.order_by(Alert.received_at.desc()).limit(10))
    ).scalars().all()

    return DashboardStats(
        total_hosts=total_hosts or 0,
        hosts_online=hosts_online or 0,
        hosts_offline=(total_hosts or 0) - (hosts_online or 0),
        unacknowledged_alerts=unacknowledged or 0,
        critical_alerts=critical or 0,
        scans_with_findings=scans_with_findings or 0,
        recent_alerts=[AlertOut.model_validate(a) for a in recent_alerts],
    )
