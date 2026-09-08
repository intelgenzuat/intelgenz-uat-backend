from fastapi import APIRouter

from intelgenz_api.modules.intel_cards.malware_reports import router as malware_reports_router
from intelgenz_api.modules.intel_cards.threat_actor_reports import (
    router as threat_actor_reports_router,
)

router = APIRouter(prefix="/intel-cards", tags=["intel cards"])
router.include_router(malware_reports_router)
router.include_router(threat_actor_reports_router)
