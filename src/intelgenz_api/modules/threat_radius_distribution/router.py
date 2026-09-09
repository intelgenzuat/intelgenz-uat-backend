"""Client-specific threat-actor radius distribution endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from intelgenz_api.core.database import get_database_session
from intelgenz_api.modules.intel_cards.schemas import (
    ThreatActorRadiusIntelCard,
    ThreatActorRadiusSeverity,
)
from intelgenz_api.modules.intel_cards.threat_actor_reports import (
    RADIUS_RANGES,
    get_threat_actor_intel_cards,
)
from intelgenz_api.modules.threat_radius_distribution.schemas import (
    ThreatActorRadiusDistributionItem,
    ThreatActorRadiusDistributionResponse,
)

router = APIRouter(prefix="/threat-radius-distribution", tags=["threat radius distribution"])

RADIUS_LIST_QUERY = text("""
    SELECT
        threat_actor.actor_id,
        threat_actor.canonical_name AS name,
        threat_actor_client_radius.radius
    FROM public.threat_actor_client_radius
    JOIN public.threat_actor
        ON threat_actor.actor_id = threat_actor_client_radius.actor_id
    WHERE LOWER(threat_actor_client_radius.client_name) = LOWER(:client_name)
    ORDER BY threat_actor_client_radius.radius, threat_actor.canonical_name, threat_actor.actor_id
""")

RADIUS_DETAIL_QUERY = text("""
    SELECT
        threat_actor_client_radius.client_name,
        threat_actor_client_radius.radius
    FROM public.threat_actor_client_radius
    WHERE threat_actor_client_radius.actor_id = :actor_id
      AND LOWER(threat_actor_client_radius.client_name) = LOWER(:client_name)
""")


def _normalized_client_name(client_name: str) -> str:
    """Validate and normalize a client name used in a radius query."""
    normalized_client_name = client_name.strip()
    if not normalized_client_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="client_name must contain at least one non-space character.",
        )
    return normalized_client_name


def _severity_for_radius(radius: float) -> ThreatActorRadiusSeverity:
    """Calculate the one severity band that contains a 0-to-5 radius score."""
    for severity, (minimum_radius, maximum_radius, maximum_inclusive) in RADIUS_RANGES.items():
        if radius >= minimum_radius and (
            radius < maximum_radius or (maximum_inclusive and radius <= maximum_radius)
        ):
            return severity
    raise ValueError(f"Radius must be between 0 and 5, received {radius}.")


@router.get("/threat-actors", response_model=ThreatActorRadiusDistributionResponse)
async def list_threat_actor_radius_distribution(
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorRadiusDistributionResponse:
    """Return lightweight actor, calculated severity, and radius data for one client."""
    normalized_client_name = _normalized_client_name(client_name)
    try:
        result = await session.execute(RADIUS_LIST_QUERY, {"client_name": normalized_client_name})
        rows = [dict(row) for row in result.mappings()]
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat radius distribution is temporarily unavailable.",
        ) from error

    return ThreatActorRadiusDistributionResponse(
        client_name=normalized_client_name,
        total_items=len(rows),
        items=[
            ThreatActorRadiusDistributionItem(
                actor_id=row["actor_id"],
                name=row["name"],
                radius=float(row["radius"]),
                severity=_severity_for_radius(float(row["radius"])),
            )
            for row in rows
        ],
    )


@router.get("/threat-actors/{actor_id}", response_model=ThreatActorRadiusIntelCard)
async def get_threat_actor_radius_report(
    actor_id: int,
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorRadiusIntelCard:
    """Return a selected actor's complete report and calculated radius severity for one client."""
    normalized_client_name = _normalized_client_name(client_name)
    try:
        result = await session.execute(
            RADIUS_DETAIL_QUERY,
            {"client_name": normalized_client_name, "actor_id": actor_id},
        )
        radius_row = result.mappings().first()
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat radius distribution is temporarily unavailable.",
        ) from error
    if radius_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat actor has no radius assessment for the requested client.",
        )

    response = await get_threat_actor_intel_cards(session=session, actor_id=actor_id)
    if not response.items:
        raise RuntimeError("The threat-actor report is unexpectedly empty.")
    report = response.items[0]
    return ThreatActorRadiusIntelCard(
        **report.model_dump(),
        client_name=normalized_client_name,
        radius=float(radius_row["radius"]),
        severity=_severity_for_radius(float(radius_row["radius"])),
    )
