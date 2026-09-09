"""Client-specific threat-actor radius distribution endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from intelgenz_api.core.database import get_database_session
from intelgenz_api.modules.intel_cards.schemas import (
    ThreatActorRadiusIntelCard,
    ThreatActorRadiusRange,
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
      AND threat_actor_client_radius.radius >= :minimum_radius
      AND (
          threat_actor_client_radius.radius < :maximum_radius
          OR (:maximum_inclusive AND threat_actor_client_radius.radius <= :maximum_radius)
      )
    ORDER BY threat_actor_client_radius.radius, threat_actor.canonical_name, threat_actor.actor_id
""")

RADIUS_DETAIL_QUERY = text("""
    SELECT
        threat_actor_client_radius.client_name,
        threat_actor_client_radius.radius
    FROM public.threat_actor_client_radius
    WHERE threat_actor_client_radius.actor_id = :actor_id
      AND LOWER(threat_actor_client_radius.client_name) = LOWER(:client_name)
      AND threat_actor_client_radius.radius >= :minimum_radius
      AND (
          threat_actor_client_radius.radius < :maximum_radius
          OR (:maximum_inclusive AND threat_actor_client_radius.radius <= :maximum_radius)
      )
""")


def _radius_query_parameters(
    client_name: str,
    severity: ThreatActorRadiusSeverity,
) -> tuple[str, ThreatActorRadiusRange, dict[str, str | float | bool]]:
    """Return normalized client name, response range, and safe SQL parameters."""
    normalized_client_name = client_name.strip()
    if not normalized_client_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="client_name must contain at least one non-space character.",
        )
    minimum_radius, maximum_radius, maximum_inclusive = RADIUS_RANGES[severity]
    return (
        normalized_client_name,
        ThreatActorRadiusRange(
            minimum=minimum_radius,
            maximum=maximum_radius,
            maximum_inclusive=maximum_inclusive,
        ),
        {
            "client_name": normalized_client_name,
            "minimum_radius": minimum_radius,
            "maximum_radius": maximum_radius,
            "maximum_inclusive": maximum_inclusive,
        },
    )


@router.get("/threat-actors", response_model=ThreatActorRadiusDistributionResponse)
async def list_threat_actor_radius_distribution(
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name."),
    ],
    severity: Annotated[ThreatActorRadiusSeverity, Query(description="Radius severity band.")],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorRadiusDistributionResponse:
    """Return lightweight actor and radius data for one client severity band."""
    normalized_client_name, radius_range, query_parameters = _radius_query_parameters(
        client_name, severity
    )
    try:
        result = await session.execute(RADIUS_LIST_QUERY, query_parameters)
        rows = [dict(row) for row in result.mappings()]
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat radius distribution is temporarily unavailable.",
        ) from error

    return ThreatActorRadiusDistributionResponse(
        client_name=normalized_client_name,
        severity=severity,
        radius_range=radius_range,
        total_items=len(rows),
        items=[
            ThreatActorRadiusDistributionItem(
                actor_id=row["actor_id"],
                name=row["name"],
                radius=float(row["radius"]),
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
    severity: Annotated[ThreatActorRadiusSeverity, Query(description="Radius severity band.")],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorRadiusIntelCard:
    """Return a selected actor's complete report and radius for a client severity band."""
    normalized_client_name, _, query_parameters = _radius_query_parameters(client_name, severity)
    try:
        result = await session.execute(
            RADIUS_DETAIL_QUERY,
            {**query_parameters, "actor_id": actor_id},
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
            detail="Threat actor is not in the requested client severity band.",
        )

    response = await get_threat_actor_intel_cards(session=session, actor_id=actor_id)
    if not response.items:
        raise RuntimeError("The threat-actor report is unexpectedly empty.")
    report = response.items[0]
    return ThreatActorRadiusIntelCard(
        **report.model_dump(),
        client_name=normalized_client_name,
        radius=float(radius_row["radius"]),
        severity=severity,
    )
