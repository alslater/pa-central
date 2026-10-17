"""Package-index (private registry) credentials and their links to repo scans."""
from __future__ import annotations

from urllib.parse import urlsplit

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CredentialType,
    RepoCredential,
    RepoScan,
    repo_scan_package_indexes,
)

MAX_INDEX_URL = 500


def index_url_problem(url: str | None) -> str | None:
    """Why *url* cannot be a package index URL, or None.

    https only, a host, and no user-info, query string or fragment: the credential belongs in
    the secret, never in a URL that is stored and displayed in clear.
    """
    if not url or not url.strip():
        return "index_url is required for credential_type 'package_index'"
    if len(url) > MAX_INDEX_URL:
        return f"index_url must be at most {MAX_INDEX_URL} characters"
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
    except ValueError:  # a malformed authority, such as an unclosed IPv6 bracket
        return "index_url is not a valid URL"
    if parts.scheme != "https":
        return "index_url must be an https:// URL"
    if not host:
        return "index_url must include a host"
    if "@" in parts.netloc:
        return "index_url must not contain credentials; put the token in the credential value"
    if "?" in url or "#" in url:
        return "index_url must not contain a query string or fragment; put the token in the credential value"
    return None


async def lock_credentials(db: AsyncSession, ids) -> None:
    """Write-lock each credential row in *ids* (None skipped) until the transaction ends.

    A credential's type is checked when a scan is assigned it, and its use is checked when its type
    changes; both take these locks first, so whichever runs second sees the other's commit and a
    package_index credential can never end up as a git credential, or the reverse. An inert
    raw-SQL write rather than SELECT ... FOR UPDATE, as elsewhere here: SQLite ignores FOR UPDATE,
    and raw SQL fires no onupdate. Sorted, so two callers locking the same rows cannot deadlock.
    """
    for cid in sorted({i for i in ids if i is not None}):
        await db.execute(text("UPDATE repo_credentials SET name = name WHERE id = :id"), {"id": cid})


async def lock_scan(db: AsyncSession, scan_id: int) -> None:
    """Write-lock the repo scan row until the transaction ends (see lock_credentials for the form).

    Replacing a scan's package-index links deletes and re-inserts them; two concurrent replacements
    must not interleave, or each misses the other's uncommitted links and the lists merge.
    """
    await db.execute(text("UPDATE repo_scans SET name = name WHERE id = :id"), {"id": scan_id})


async def credential_in_use(db: AsyncSession, credential_id: int) -> bool:
    """True when a repo scan uses the credential, as its git credential or as a package index."""
    row = await db.execute(select(RepoScan.id).where(RepoScan.credential_id == credential_id).limit(1))
    if row.first() is not None:
        return True
    return await linked_scan_exists(db, credential_id)


async def linked_scan_exists(db: AsyncSession, credential_id: int) -> bool:
    row = await db.execute(
        select(repo_scan_package_indexes.c.repo_scan_id)
        .where(repo_scan_package_indexes.c.credential_id == credential_id).limit(1))
    return row.first() is not None


async def index_ids_by_scan(db: AsyncSession, scan_ids: list[int]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {sid: [] for sid in scan_ids}
    if not scan_ids:
        return out
    rows = await db.execute(
        select(repo_scan_package_indexes.c.repo_scan_id, repo_scan_package_indexes.c.credential_id)
        .where(repo_scan_package_indexes.c.repo_scan_id.in_(scan_ids))
        .order_by(repo_scan_package_indexes.c.credential_id))
    for scan_id, cred_id in rows:
        out[scan_id].append(cred_id)
    return out


async def index_credentials(db: AsyncSession, scan_id: int) -> list[RepoCredential]:
    rows = await db.execute(
        select(RepoCredential)
        .join(repo_scan_package_indexes, repo_scan_package_indexes.c.credential_id == RepoCredential.id)
        .where(repo_scan_package_indexes.c.repo_scan_id == scan_id)
        .order_by(RepoCredential.id))
    return list(rows.scalars().all())


async def ids_problem(db: AsyncSession, ids: list[int]) -> str | None:
    """Why *ids* cannot be a repo scan's package indexes, or None."""
    if len(set(ids)) != len(ids):
        return "package_index_credential_ids must not repeat"
    if not ids:
        return None
    rows = await db.execute(select(RepoCredential.id, RepoCredential.credential_type)
                            .where(RepoCredential.id.in_(ids)))
    found = dict(rows.all())
    missing = sorted(set(ids) - set(found))
    if missing:
        return f"credential(s) not found: {missing}"
    wrong = sorted(i for i, t in found.items() if t != CredentialType.package_index)
    if wrong:
        return f"credential(s) {wrong} are not package_index credentials"
    return None


async def set_index_ids(db: AsyncSession, scan_id: int, ids: list[int]) -> None:
    """Replace the scan's links (caller validated *ids* with ids_problem and commits)."""
    await db.execute(repo_scan_package_indexes.delete().where(repo_scan_package_indexes.c.repo_scan_id == scan_id))
    if ids:
        await db.execute(repo_scan_package_indexes.insert(),
                         [{"repo_scan_id": scan_id, "credential_id": i} for i in ids])
