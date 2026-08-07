from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_operator
from app.core.database import get_db
from app.models import ConfigAssignment, ConfigTemplate, Host, User
from app.schemas import (
    ConfigAssignOut,
    ConfigTemplateCreate,
    ConfigTemplateOut,
    ConfigTemplateUpdate,
    LintResult,
    ValidateRequest,
)
from app.services.config_lint import lint_toml

router = APIRouter(prefix="/config-templates", tags=["config"])


_MAX_VALIDATE_BYTES = 64 * 1024  # 64 KB — well above any real config template


@router.post("/validate", response_model=LintResult)
async def validate_template(
    body: ValidateRequest,
    _: User = Depends(get_current_user),
) -> LintResult:
    if len(body.toml_content.encode()) > _MAX_VALIDATE_BYTES:
        raise HTTPException(413, detail=f"Payload exceeds maximum allowed size ({_MAX_VALIDATE_BYTES // 1024} KB)")
    return lint_toml(body.toml_content)


@router.get("", response_model=list[ConfigTemplateOut])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[ConfigTemplateOut]:
    result = await db.execute(select(ConfigTemplate).order_by(ConfigTemplate.name))
    return result.scalars().all()


@router.post("", response_model=ConfigTemplateOut, status_code=201)
async def create_template(
    body: ConfigTemplateCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
) -> ConfigTemplateOut:
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
) -> ConfigTemplateOut:
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
) -> ConfigTemplateOut:
    tmpl = await db.get(ConfigTemplate, tmpl_id)
    if not tmpl:
        raise HTTPException(404, "Template not found")

    update_data = body.model_dump(exclude_none=True)

    if "is_default" in body.model_fields_set:
        if body.is_default:
            others = (await db.execute(
                select(ConfigTemplate).where(
                    ConfigTemplate.is_default.is_(True),
                    ConfigTemplate.id != tmpl_id,
                )
            )).scalars().all()
            for other in others:
                other.is_default = False
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
) -> None:
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
) -> ConfigAssignOut:
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
) -> ConfigTemplateOut | None:
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
