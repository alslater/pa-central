import asyncio
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_operator, require_viewer
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import Alert, AlertSeverity, Host, User, UserRole, utcnow
from app.schemas import AlertAcknowledge, AlertBulkAcknowledge, AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])

# How often stream_alerts re-checks that the connection's bearer token is
# still valid. Decoupled from alert volume deliberately: gating the check on
# time elapsed rather than on every loop iteration means a burst of alerts
# does not turn into a burst of extra DB queries, one per alert, on top of
# whatever the burst itself already costs.
SSE_EPOCH_RECHECK_INTERVAL_SECONDS = 25.0


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    host_id: int | None = Query(None),
    severity: AlertSeverity | None = Query(None),
    acknowledged: bool | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
) -> list[AlertOut]:
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
async def stream_alerts(request: Request) -> Response:
    from app.core.database import AsyncSessionLocal
    auth_header = request.headers.get("authorization", "")
    raw_token = auth_header[7:] if auth_header.lower().startswith("bearer ") else ""
    decoded = decode_access_token(raw_token)
    if not decoded:
        return Response(status_code=401)
    user_id, token_epoch = decoded
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
        # See app.api.deps.get_current_user — same reasoning, duplicated
        # because this endpoint authenticates by hand rather than through the
        # usual FastAPI dependency (it needs to close the session before
        # opening the SSE stream, which the dependency doesn't support).
        if token_epoch != user.token_epoch:
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

    async def still_authorized() -> bool:
        # Re-checked periodically (see event_generator below), not just at
        # connect time: the check above only ran once, before the
        # StreamingResponse started, so a stream opened before a password
        # reset kept delivering alerts indefinitely afterward — every other
        # request with the same JWT started 401ing, but this one, once
        # established, never looked at the epoch again. A short-lived
        # session per check, matching the connect-time check above, rather
        # than holding one for the stream's lifetime.
        #
        # Re-decodes the token itself first, not just the database side.
        # decode_access_token checks `exp` (jwt.decode does this by default),
        # but it was previously only ever called once, at connect time —
        # every ordinary HTTP endpoint re-decodes on every single request, so
        # expiry is naturally re-checked constantly there, but this stream
        # authenticates once and then holds the connection open indefinitely.
        # A stream opened one second before the 8-hour expiry therefore kept
        # delivering alerts past it, since token_epoch/is_active have nothing
        # to do with the token's own exp claim — a deactivated-or-reset
        # account was caught, but a token that had simply run out never was.
        # get_current_user (api/deps.py) never has this gap: a normal request
        # cannot outlive its own auth check the way a held-open stream can.
        if not decode_access_token(raw_token):
            return False
        async with AsyncSessionLocal() as check_db:
            row = (await check_db.execute(
                select(User.token_epoch, User.is_active).where(User.id == uid)
            )).first()
        return row is not None and row.is_active and row.token_epoch == token_epoch

    async def event_generator():
        # Gated on elapsed time, not on every loop iteration: a busy queue
        # would otherwise turn a burst of alerts into a burst of extra DB
        # queries, one per alert, on top of whatever the burst itself
        # already costs. A quiet stream still gets checked every interval
        # via the keepalive timeout below, so this is a ceiling on
        # revalidation frequency, not a floor on how often the loop spins.
        last_checked = time.monotonic()
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                now = time.monotonic()
                if now - last_checked >= SSE_EPOCH_RECHECK_INTERVAL_SECONDS:
                    last_checked = now
                    if not await still_authorized():
                        break
                try:
                    alert = await asyncio.wait_for(
                        queue.get(), timeout=SSE_EPOCH_RECHECK_INTERVAL_SECONDS
                    )
                    if allowed_host_ids is not None and alert.get("host_id") not in allowed_host_ids:
                        continue
                    yield f"data: {json.dumps(alert)}\n\n"
                except TimeoutError:
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
) -> AlertOut:
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
) -> None:
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
) -> AlertOut:
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = body.acknowledged
    alert.acknowledged_by_id = user.id if body.acknowledged else None
    alert.acknowledged_at = utcnow() if body.acknowledged else None
    await db.commit()
    await db.refresh(alert)
    return alert
