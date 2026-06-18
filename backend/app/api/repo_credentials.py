"""Repo credential CRUD — shared credentials for repo scanning."""
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings as app_settings
from app.core.aws import SecretsManagerClient
from app.models import RepoCredential, CredentialType, User, utcnow
from app.schemas import RepoCredentialCreate, RepoCredentialUpdate, RepoCredentialOut
from app.api.deps import require_operator, require_admin

router = APIRouter(prefix="/repo-credentials", tags=["repo-credentials"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
OperatorDep = Annotated[User, Depends(require_operator)]
AdminDep = Annotated[User, Depends(require_admin)]


def _sm() -> SecretsManagerClient:
    return SecretsManagerClient(endpoint_url=app_settings.aws_endpoint_url, region_name=app_settings.aws_region)


def _secret_name(cred_id: int) -> str:
    return f"pa-central/repo-creds/{cred_id}"


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


@router.get("", response_model=list[RepoCredentialOut])
async def list_credentials(db: DbDep, _: OperatorDep):
    result = await db.execute(select(RepoCredential).order_by(RepoCredential.name))
    return result.scalars().all()


@router.post("", status_code=201, response_model=RepoCredentialOut)
async def create_credential(body: RepoCredentialCreate, db: DbDep, _: OperatorDep):
    if body.credential_type != CredentialType.none and not body.credential_value:
        raise HTTPException(400, "credential_value is required when credential_type is not 'none'")
    if body.credential_type == CredentialType.none and body.credential_value:
        raise HTTPException(400, "credential_value must not be set when credential_type is 'none'")
    if body.ssh_key_passphrase and body.credential_type != CredentialType.ssh_key:
        raise HTTPException(400, "ssh_key_passphrase is only valid for credential_type 'ssh_key'")
    cred = RepoCredential(
        name=body.name,
        credential_type=body.credential_type,
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
async def update_credential(cred_id: int, body: RepoCredentialUpdate, db: DbDep, _: OperatorDep):
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
    for k, v in updates.items():
        setattr(cred, k, v)
    if cred.credential_type == CredentialType.none:
        # Clear any stored secret when switching to no-credential mode.
        if cred.credential_secret_arn:
            if not cred.credential_secret_arn.startswith("local://"):
                try:
                    await _sm().delete_secret(cred.credential_secret_arn)
                except Exception:
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
    cred = await db.get(RepoCredential, cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    # Prevent deletion if any scan references this credential
    from app.models import RepoScan
    in_use = await db.execute(select(RepoScan).where(RepoScan.credential_id == cred_id).limit(1))
    if in_use.scalar_one_or_none():
        raise HTTPException(409, "Credential is in use by one or more repo scans")
    if cred.credential_secret_arn and not cred.credential_secret_arn.startswith("local://"):
        try:
            await _sm().delete_secret(cred.credential_secret_arn)
        except Exception:
            pass
    await db.delete(cred)
    await db.commit()
