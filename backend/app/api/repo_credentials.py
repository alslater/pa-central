"""Repo credential CRUD — shared credentials for repo scanning."""
import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_operator
from app.core.aws import SecretsManagerClient
from app.core.config import settings as app_settings
from app.core.database import get_db
from app.models import CredentialType, RepoCredential, User, utcnow
from app.schemas import RepoCredentialCreate, RepoCredentialOut, RepoCredentialUpdate
from app.services.package_indexes import (
    credential_in_use,
    index_url_problem,
    lock_credentials,
)

router = APIRouter(prefix="/repo-credentials", tags=["repo-credentials"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
OperatorDep = Annotated[User, Depends(require_operator)]
AdminDep = Annotated[User, Depends(require_admin)]


def _sm() -> SecretsManagerClient:
    return SecretsManagerClient(endpoint_url=app_settings.aws_endpoint_url, region_name=app_settings.aws_region)


def _secret_name(cred_id: int) -> str:
    """A new secret's name. Unique, not just the credential id: SQLite reuses the highest id after a
    delete, and a deleted credential's secret is removed only after its row (delete_credential), so a
    credential created in between would otherwise ask for a name that still exists. Every later
    operation uses the stored ARN, never this name."""
    return f"pa-central/repo-creds/{cred_id}-{uuid.uuid4().hex}"


def _normalize_pem(value: str) -> str:
    """Ensure a PEM key has proper line breaks regardless of how it was pasted."""
    import re
    header = re.search(r'(-----BEGIN [^-]+-----)', value)
    footer = re.search(r'(-----END [^-]+-----)', value)
    if not header or not footer:
        return value
    between = value[header.end():value.index(footer.group(0))].strip()
    # Insert newlines before RFC 1421 header keywords if fused
    between = re.sub(r'(Proc-Type|DEK-Info)\s*:', r'\n\1:', between)
    pem_headers = []
    body_parts = []
    for line in between.split('\n'):
        t = line.strip()
        if not t:
            continue
        m_proc = re.match(r'^Proc-Type:\s*(\S+)(.*)', t)
        m_dek  = re.match(r'^DEK-Info:\s*([A-Z0-9-]+,[0-9A-Fa-f]+)(.*)', t)
        if m_proc:
            pem_headers.append(f"Proc-Type: {m_proc.group(1)}")
            if m_proc.group(2):
                body_parts.append(re.sub(r'\s+', '', m_proc.group(2)))
        elif m_dek:
            pem_headers.append(f"DEK-Info: {m_dek.group(1)}")
            if m_dek.group(2):
                body_parts.append(re.sub(r'\s+', '', m_dek.group(2)))
        else:
            body_parts.append(re.sub(r'\s+', '', t))
    body = ''.join(body_parts)
    wrapped = '\n'.join(body[i:i+64] for i in range(0, len(body), 64))
    parts = [header.group(0)] + pem_headers + ([''] if pem_headers else []) + [wrapped, footer.group(0)]
    return '\n'.join(parts)


def _encode_credential(value: str, passphrase: str | None) -> str:
    if passphrase:
        return json.dumps({"key": value, "passphrase": passphrase})
    return value


def _check_index_fields(ctype: CredentialType, index_url: str | None, index_username: str | None) -> None:
    if ctype == CredentialType.package_index:
        problem = index_url_problem(index_url)
        if problem:
            raise HTTPException(400, problem)
    elif index_url is not None or index_username is not None:
        raise HTTPException(400, "index_url and index_username are only valid for credential_type 'package_index'")


@router.get("", response_model=list[RepoCredentialOut])
async def list_credentials(db: DbDep, _: OperatorDep) -> list[RepoCredentialOut]:
    result = await db.execute(select(RepoCredential).order_by(RepoCredential.name))
    return result.scalars().all()


@router.post("", status_code=201, response_model=RepoCredentialOut)
async def create_credential(body: RepoCredentialCreate, db: DbDep, _: OperatorDep) -> RepoCredentialOut:
    if body.credential_type != CredentialType.none and not body.credential_value:
        raise HTTPException(400, "credential_value is required when credential_type is not 'none'")
    if body.credential_type == CredentialType.none and body.credential_value:
        raise HTTPException(400, "credential_value must not be set when credential_type is 'none'")
    if body.ssh_key_passphrase and body.credential_type != CredentialType.ssh_key:
        raise HTTPException(400, "ssh_key_passphrase is only valid for credential_type 'ssh_key'")
    _check_index_fields(body.credential_type, body.index_url, body.index_username)
    cred = RepoCredential(
        name=body.name,
        credential_type=body.credential_type,
        index_url=body.index_url.strip() if body.index_url else None,
        index_username=body.index_username or None,
    )
    db.add(cred)
    await db.flush()
    if body.credential_value:
        value = _normalize_pem(body.credential_value) if body.credential_type == CredentialType.ssh_key else body.credential_value
        secret_str = _encode_credential(value, body.ssh_key_passphrase)
        if app_settings.local_docker_scan:
            if not app_settings.debug:
                raise HTTPException(500, "local_docker_scan requires DEBUG=true — refusing to store credentials inline in production")
            cred.credential_secret_arn = f"local://{secret_str}"
        else:
            arn = await _sm().create_secret(_secret_name(cred.id), secret_str)
            cred.credential_secret_arn = arn
    await db.commit()
    return cred


@router.patch("/{cred_id}", response_model=RepoCredentialOut)
async def update_credential(cred_id: int, body: RepoCredentialUpdate, db: DbDep, _: OperatorDep) -> RepoCredentialOut:
    # Before the reads below: the in-use check must not race a scan being assigned it.
    await lock_credentials(db, [cred_id])
    cred = await db.get(RepoCredential, cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    updates = body.model_dump(exclude_none=True)
    credential_value = updates.pop("credential_value", None)
    ssh_key_passphrase = updates.pop("ssh_key_passphrase", None)
    new_type = updates.get("credential_type")
    effective_type = new_type or cred.credential_type
    # Changing credential_type without supplying a new value would leave the
    # stored secret mismatched with the type (e.g. SSH key stored as https_token).
    if new_type and new_type != CredentialType.none and new_type != cred.credential_type and not credential_value:
        raise HTTPException(400, "Provide a new credential_value when changing credential_type")
    if ssh_key_passphrase and effective_type != CredentialType.ssh_key:
        raise HTTPException(400, "ssh_key_passphrase is only valid for credential_type 'ssh_key'")
    # A scan's git credential must stay a git type, and a linked package index must stay a
    # package index: changing the type would break every scan that uses it.
    if effective_type != cred.credential_type and await credential_in_use(db, cred_id):
        raise HTTPException(409, "Credential is in use by one or more repo scans; its type cannot change")
    carried = effective_type == cred.credential_type
    # model_dump(exclude_none) drops an explicit null, which here means "clear it" (a token
    # instead of a username and password): only an omitted field keeps the stored value.
    sent = body.model_fields_set
    effective_url = body.index_url if "index_url" in sent else (cred.index_url if carried else None)
    effective_user = body.index_username if "index_username" in sent else (cred.index_username if carried else None)
    _check_index_fields(effective_type, effective_url, effective_user)
    updates["index_url"] = effective_url.strip() if effective_url else None
    updates["index_username"] = effective_user or None
    for k, v in updates.items():
        setattr(cred, k, v)
    if cred.credential_type == CredentialType.none:
        # Clear any stored secret when switching to no-credential mode.
        if cred.credential_secret_arn:
            if not cred.credential_secret_arn.startswith("local://"):
                try:
                    await _sm().delete_secret(cred.credential_secret_arn)
                except Exception:  # noqa: BLE001 S110
                    pass
            cred.credential_secret_arn = None
    elif credential_value:
        value = _normalize_pem(credential_value) if cred.credential_type == CredentialType.ssh_key else credential_value
        secret_str = _encode_credential(value, ssh_key_passphrase)
        if app_settings.local_docker_scan:
            if not app_settings.debug:
                raise HTTPException(500, "local_docker_scan requires DEBUG=true — refusing to store credentials inline in production")
            cred.credential_secret_arn = f"local://{secret_str}"
        elif cred.credential_secret_arn and not cred.credential_secret_arn.startswith("local://"):
            await _sm().update_secret(cred.credential_secret_arn, secret_str)
        else:
            arn = await _sm().create_secret(_secret_name(cred.id), secret_str)
            cred.credential_secret_arn = arn
    cred.updated_at = utcnow()
    await db.commit()
    return cred


@router.delete("/{cred_id}", status_code=204)
async def delete_credential(cred_id: int, db: DbDep, _: AdminDep) -> None:
    # Before the reads below: the in-use check must not race a scan being assigned it.
    await lock_credentials(db, [cred_id])
    cred = await db.get(RepoCredential, cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    # Prevent deletion if any scan references this credential
    if await credential_in_use(db, cred_id):
        raise HTTPException(409, "Credential is in use by one or more repo scans")
    arn = cred.credential_secret_arn
    await db.delete(cred)
    await db.commit()
    # Only once the row is gone: a delete that fails to commit must not have destroyed the secret
    # a credential still points at (at worst, a failure here leaves an orphaned secret).
    if arn and not arn.startswith("local://"):
        try:
            await _sm().delete_secret(arn)
        except Exception:  # noqa: BLE001 S110
            pass
