"""Client-specific threat-actor radius distribution endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from intelgenz_api.core.database import get_database_session
from intelgenz_api.modules.intel_cards.schemas import (
    ThreatActorRadiusIntelCardResponse,
    ThreatActorRadiusSeverity,
)
from intelgenz_api.modules.intel_cards.threat_actor_reports import get_threat_actor_intel_cards

router = APIRouter(prefix="/threat-radius-distribution", tags=["threat radius distribution"])


@router.get("/threat-actors", response_model=ThreatActorRadiusIntelCardResponse)
async def get_threat_actor_radius_distribution(
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name."),
    ],
    severity: Annotated[ThreatActorRadiusSeverity, Query(description="Radius severity band.")],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorRadiusIntelCardResponse:
    """Return every complete threat-actor card within a client's requested radius band."""
    response = await get_threat_actor_intel_cards(
        session=session,
        client_name=client_name,
        severity=severity,
    )
    if not isinstance(response, ThreatActorRadiusIntelCardResponse):
        raise RuntimeError("The threat radius distribution did not return a radius response.")
    return response
