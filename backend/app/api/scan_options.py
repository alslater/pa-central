from fastapi import APIRouter, Depends

from app.models import User
from app.api.deps import get_current_user
from app.schemas import ScanOptions
from app.services.scan_options import get_scan_options

router = APIRouter(prefix="/repo-scans", tags=["repo-scans"])


@router.get("/scan-options", response_model=ScanOptions)
async def scan_options(_: User = Depends(get_current_user)):
    return get_scan_options()
