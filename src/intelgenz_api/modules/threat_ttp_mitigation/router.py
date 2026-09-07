from fastapi import APIRouter

from intelgenz_api.modules.threat_ttp_mitigation.malware import router as malware_router

router = APIRouter(prefix="/threat-ttps")
router.include_router(malware_router)
