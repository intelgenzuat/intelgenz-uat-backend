from fastapi import APIRouter

from intelgenz_api.modules.emerging_threats.reports import router as reports_router

router = APIRouter(prefix="/emerging-threats", tags=["emerging threats"])
router.include_router(reports_router)
