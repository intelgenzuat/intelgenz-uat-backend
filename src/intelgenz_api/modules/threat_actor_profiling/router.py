from fastapi import APIRouter

from intelgenz_api.modules.threat_actor_profiling.threat_actor import router as threat_actor_router

router = APIRouter(prefix="/threat-actors")
router.include_router(threat_actor_router)
