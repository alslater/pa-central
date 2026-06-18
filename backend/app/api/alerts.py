import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import Alert, Host, User, AlertSeverity, UserRole, utcnow
from app.schemas import AlertOut, AlertAcknowledge, AlertBulkAcknowledge
from app.api.deps import require_operator, require_viewer

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    host_id: int | None = Query(None),
    severity: AlertSeverity | None = Query(None),
    acknowledged: bool | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    q = select(Alert).order_by(Alert.received_at.desc()).limit(limit).offset(offset)
    if host_id is not None:
        q = q.where(Alert.host_id == host_id)
    if severity is not None:
        q = q.where(Alert.severity == severity)
    if acknowledged is not None:
        q = q.where(Alert.acknowledged.is_(acknowledged))
    # Developers see only their own hosts' alerts; all other roles (viewer and above)
    # have fleet-wide read access by design — viewers are trusted observers of the
    # whole fleet, not scoped to individual hosts.
    if user.role == UserRole.developer:
        owned_subq = select(Host.id).where(Host.owner_user_id == user.id).scalar_subquery()
        q = q.where(Alert.host_id.in_(owned_subq))
    result = await db.execute(q)
    return result.scalars().all()


# ── SSE live feed — must be registered before /{alert_id} to avoid shadowing ──

# Global set of queues — one per connected SSE client
_sse_queues: set[asyncio.Queue] = set()


def broadcast_alert(alert_dict: dict) -> None:
    """Called by the ingest endpoint after a new alert is saved."""
    for q in list(_sse_queues):
        if q.full():
            try:
                q.get_nowait()  # drop oldest to make room
            except asyncio.QueueEmpty:
                pass
        try:
            q.put_nowait(alert_dict)
        except asyncio.QueueFull:
            pass  # race between full() check and put_nowait — skip this client


@router.get("/stream", include_in_schema=True)
async def stream_alerts(request: Request):
    from app.core.database import AsyncSessionLocal
    auth_header = request.headers.get("authorization", "")
    raw_token = auth_header[7:] if auth_header.lower().startswith("bearer ") else ""
    user_id = decode_access_token(raw_token)
    if not user_id:
        return Response(status_code=401)
    try:
        uid = int(user_id)
    except ValueError:
        return Response(status_code=401)

    # Open a session only for the auth/scope lookup, then close it before
    # returning the StreamingResponse so we don't hold a connection for the
    # lifetime of the SSE stream.
    async with AsyncSessionLocal() as db:
        user = await db.get(User, uid)
        if not user or not user.is_active:
            return Response(status_code=401)

        # Developers are scoped to their own hosts, matching list_alerts behaviour.
        # All other roles (viewer and above) have fleet-wide read access.
        allowed_host_ids: frozenset[int] | None = None
        if user.role == UserRole.developer:
            rows = (await db.execute(
                select(Host.id).where(Host.owner_user_id == user.id)
            )).scalars().all()
            allowed_host_ids = frozenset(rows)

    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_queues.add(queue)

    async def event_generator():
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=25)
                    if allowed_host_ids is not None and alert.get("host_id") not in allowed_host_ids:
                        continue
                    yield f"data: {json.dumps(alert)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _sse_queues.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    if user.role == UserRole.developer:
        host = await db.get(Host, alert.host_id)
        if not host or host.owner_user_id != user.id:
            raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/acknowledge-bulk", status_code=204)
async def acknowledge_alerts_bulk(
    body: AlertBulkAcknowledge,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
):
    if not body.alert_ids:
        return
    now = utcnow()
    result = await db.execute(select(Alert).where(Alert.id.in_(body.alert_ids)))
    alerts = result.scalars().all()
    for alert in alerts:
        alert.acknowledged = body.acknowledged
        alert.acknowledged_by_id = user.id if body.acknowledged else None
        alert.acknowledged_at = now if body.acknowledged else None
    await db.commit()


@router.patch("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: int,
    body: AlertAcknowledge,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = body.acknowledged
    alert.acknowledged_by_id = user.id if body.acknowledged else None
    alert.acknowledged_at = utcnow() if body.acknowledged else None
    await db.commit()
    await db.refresh(alert)
    return alert
