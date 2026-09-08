from fastapi import APIRouter, status

from intelgenz_api.modules.emerging_threats.router import router as emerging_threats_router
from intelgenz_api.modules.intel_cards.router import router as intel_cards_router
from intelgenz_api.modules.threat_actor_profiling.router import (
    router as threat_actor_profiling_router,
)
from intelgenz_api.modules.threat_radius_distribution.router import (
    router as threat_radius_distribution_router,
)
from intelgenz_api.modules.threat_ttp_mitigation.router import (
    router as threat_ttp_mitigation_router,
)

api_router = APIRouter()
api_router.include_router(emerging_threats_router)
api_router.include_router(intel_cards_router)
api_router.include_router(threat_ttp_mitigation_router)
api_router.include_router(threat_actor_profiling_router)
api_router.include_router(threat_radius_distribution_router)


@api_router.get("/health", status_code=status.HTTP_200_OK, tags=["health"])
async def health_check() -> dict[str, str]:
    """Return the service liveness status."""
    return {"status": "ok"}
