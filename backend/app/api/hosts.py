from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Select, String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_operator
from app.core.database import get_db
from app.models import Host, Scan, User, UserRole
from app.schemas import HostOut, HostUpdate, ScanOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[HostOut]:
    if user.role == UserRole.admin:
        result = await db.execute(select(Host).order_by(Host.name))
    else:
        result = await db.execute(
            select(Host).where(Host.owner_user_id == user.id).order_by(Host.name)
        )
    return result.scalars().all()


@router.get("/{host_id}", response_model=HostOut)
async def get_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> HostOut:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")
    return host


@router.get("/{host_id}/latest-scans", response_model=list[ScanOut])
async def get_host_latest_scans(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ScanOut]:
    """One row per distinct (project_path, scan_type) on this host — its most recent scan,
    less any tools directory a newer `pa scan-tools` run no longer reports (_retired_tools_roots).

    GET /scans applies a default/max row limit (it's also the package-alert
    CLI's live surface and must not change shape), so grouping its results
    client-side silently drops projects once a host has more scans than that
    limit. This ranks per project in SQL instead, with no row cap, so every
    project on the host is represented regardless of total scan history depth.

    Ranked primarily by scanned_at desc, with received_at desc and id desc as
    tie-breakers for equal scanned_at (e.g. a retried/resubmitted scan) — this
    preserves the previous client-side behaviour, which iterated GET /scans'
    received_at-desc-ordered rows and kept the first (i.e. most recently
    received) match per project.

    The returned rows are ordered by scanned_at desc — most recently scanned
    project first, not alphabetically by project_path — with the same
    received_at desc, id desc tie-breakers as the ranking above, since
    different projects commonly share a scan timestamp (e.g. scans triggered
    together) and scanned_at alone would leave their relative order
    unspecified, varying between requests.
    """
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")

    rank = (
        func.row_number()
        .over(
            # scan_type too: a project and its --scan-installed environment share a path. And
            # home and manager (NULL for other scan types): a system-wide tools root is one
            # path for several accounts, each with its own runs that list or retire it.
            partition_by=(Scan.project_path, Scan.scan_type, Scan.home, Scan.manager),
            order_by=(Scan.scanned_at.desc(), Scan.received_at.desc(), Scan.id.desc()),
        )
        .label("rank")
    )
    ranked = (
        select(Scan.id, rank)
        .where(Scan.host_id == host_id)
        .subquery()
    )
    latest_ids = select(ranked.c.id).where(ranked.c.rank == 1)
    result = await db.execute(
        select(Scan).where(Scan.id.in_(latest_ids))
        .order_by(Scan.scanned_at.desc(), Scan.received_at.desc(), Scan.id.desc())
    )
    scans = list(result.scalars().all())
    retired = await _retired_tools_roots(db, host_id, scans)
    return [s for s in scans if s.id not in retired]


async def _retired_tools_roots(db: AsyncSession, host_id: int, latest: list[Scan]) -> set[int]:
    """The ids of tools scans whose directory the newest run for their (home, manager) left out.

    A tools directory that disappears (a leftover pipx layout deleted, PIPX_HOME moved) is
    never reported again, so its last scan would otherwise show forever. For each (home,
    manager), only the newest run counts, by its shared scanned_at with received_at breaking
    a tie, so a late or retried older payload never retires a root or brings one back. Every
    payload of a run carries the run_roots of all its managers_scanned, so any one of them
    speaks for each of those managers, even when another manager's payload is lost. A
    payload without home (an older client) is a scope of its own; one without run_roots
    retires nothing. Retired scans are only hidden here: they stay in GET /scans.

    The newest run is looked up in the host's history, not in *latest*: a later run of
    another manager can replace the row that carried it there.
    """
    scopes = {(s.home, s.manager) for s in latest if s.scan_type == "tools" and s.manager is not None}
    run_roots = {scope: await _newest_run_roots(db, host_id, *scope) for scope in scopes}
    return {
        s.id for s in latest
        if s.scan_type == "tools"
        and (roots := run_roots.get((s.home, s.manager))) is not None
        and s.project_path not in roots
    }


async def _newest_run_roots(db: AsyncSession, host_id: int, home: str | None, manager: str) -> list[str] | None:
    """run_roots of the newest tools scan for *home* that covers *manager*, as its own manager
    or in managers_scanned. managers_scanned is matched in its JSON text, quoted so "pip"
    cannot match "pipx"; contains() escapes LIKE wildcards. There is always such a scan: the
    latest row the scope came from."""
    row = (await db.execute(_newest_run_stmt(host_id, home, manager))).first()
    return row.run_roots if row is not None else None


def _newest_run_stmt(host_id: int, home: str | None, manager: str) -> Select[tuple[int, Any]]:
    """The query behind _newest_run_roots. ix_scans_host_type_home_scanned_received_id serves
    its filter and order, so it reads newest first and stops at the first match."""
    return (
        select(Scan.id, Scan.run_roots)
        .where(
            Scan.host_id == host_id, Scan.scan_type == "tools",
            Scan.home.is_(None) if home is None else Scan.home == home,
            or_(Scan.manager == manager,
                cast(Scan.managers_scanned, String).contains(f'"{manager}"', autoescape=True)),
        )
        .order_by(Scan.scanned_at.desc(), Scan.received_at.desc(), Scan.id.desc())
        .limit(1)
    )


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(
    host_id: int,
    body: HostUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
) -> HostOut:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(host, k, v)
    await db.commit()
    await db.refresh(host)
    return host


@router.delete("/{host_id}", status_code=204)
async def delete_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> None:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    await db.delete(host)
    await db.commit()
