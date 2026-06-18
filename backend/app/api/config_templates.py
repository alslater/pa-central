from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import ConfigTemplate, ConfigAssignment, Host, User
from app.schemas import (
    ConfigTemplateCreate, ConfigTemplateUpdate, ConfigTemplateOut, ConfigAssignOut
)
from app.api.deps import get_current_user, require_operator, require_admin

router = APIRouter(prefix="/config-templates", tags=["config"])


@router.get("", response_model=list[ConfigTemplateOut])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(ConfigTemplate).order_by(ConfigTemplate.name))
    return result.scalars().all()


@router.post("", response_model=ConfigTemplateOut, status_code=201)
async def create_template(
    body: ConfigTemplateCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
):
    tmpl = ConfigTemplate(**body.model_dump(), created_by_id=user.id)
    db.add(tmpl)
    await db.commit()
    await db.refresh(tmpl)
    return tmpl


@router.get("/{tmpl_id}", response_model=ConfigTemplateOut)
async def get_template(
    tmpl_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    tmpl = await db.get(ConfigTemplate, tmpl_id)
    if not tmpl:
        raise HTTPException(404, "Template not found")
    return tmpl


@router.patch("/{tmpl_id}", response_model=ConfigTemplateOut)
async def update_template(
    tmpl_id: int,
    body: ConfigTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_operator),
):
    tmpl = await db.get(ConfigTemplate, tmpl_id)
    if not tmpl:
        raise HTTPException(404, "Template not found")

    update_data = body.model_dump(exclude_none=True)

    if "is_default" in body.model_fields_set:
        if body.is_default:
            existing = (await db.execute(
                select(ConfigTemplate).where(ConfigTemplate.is_default.is_(True))
            )).scalar_one_or_none()
            if existing and existing.id != tmpl_id:
                existing.is_default = False
            tmpl.is_default = True
        else:
            tmpl.is_default = False
        update_data.pop("is_default", None)

    for k, v in update_data.items():
        setattr(tmpl, k, v)

    await db.commit()
    await db.refresh(tmpl)
    return tmpl


@router.delete("/{tmpl_id}", status_code=204)
async def delete_template(
    tmpl_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    from sqlalchemy import func
    from app.models import RepoScan
    tmpl = await db.get(ConfigTemplate, tmpl_id)
    if not tmpl:
        raise HTTPException(404, "Template not found")

    host_count = (await db.execute(
        select(func.count()).select_from(ConfigAssignment)
        .where(ConfigAssignment.template_id == tmpl_id)
    )).scalar() or 0
    repo_count = (await db.execute(
        select(func.count()).select_from(RepoScan)
        .where(RepoScan.config_template_id == tmpl_id)
    )).scalar() or 0

    if host_count or repo_count:
        parts = []
        if host_count:
            parts.append(f"{host_count} host(s)")
        if repo_count:
            parts.append(f"{repo_count} repo scan(s)")
        raise HTTPException(409, f"Template is assigned to {' and '.join(parts)}")

    await db.delete(tmpl)
    await db.commit()


@router.post("/{tmpl_id}/assign/{host_id}", response_model=ConfigAssignOut, status_code=201)
async def assign_template(
    tmpl_id: int,
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
):
    tmpl = await db.get(ConfigTemplate, tmpl_id)
    host = await db.get(Host, host_id)
    if not tmpl or not host:
        raise HTTPException(404, "Template or host not found")
    assignment = ConfigAssignment(host_id=host_id, template_id=tmpl_id, assigned_by_id=user.id)
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return assignment


@router.get("/for-host/{host_id}", response_model=ConfigTemplateOut | None)
async def config_for_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Returns the assigned config template for a host. Called by the frontend UI; requires a user JWT."""
    result = await db.execute(
        select(ConfigAssignment)
        .where(ConfigAssignment.host_id == host_id)
        .order_by(ConfigAssignment.assigned_at.desc())
        .limit(1)
    )
    assignment = result.scalar_one_or_none()
    if not assignment:
        return None
    return await db.get(ConfigTemplate, assignment.template_id)
