"""Paginated threat-actor intelligence cards backed by PostgreSQL."""

import re
from collections import defaultdict
from math import ceil
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import TextClause

from intelgenz_api.core.database import get_database_session
from intelgenz_api.modules.intel_cards.malware_reports import MALWARE_CARDS_PER_PAGE
from intelgenz_api.modules.intel_cards.schemas import (
    MalwareCardPagination,
    ThreatActorCardCapability,
    ThreatActorCardDate,
    ThreatActorCardExecution,
    ThreatActorCardExecutionPath,
    ThreatActorCardExecutionStep,
    ThreatActorCardInfrastructure,
    ThreatActorCardIoc,
    ThreatActorCardLastSeen,
    ThreatActorCardMotivation,
    ThreatActorCardNexus,
    ThreatActorCardObservedActivity,
    ThreatActorCardSummary,
    ThreatActorCardTargetedAsset,
    ThreatActorCardTargeting,
    ThreatActorCardTimelineItem,
    ThreatActorCardTtp,
    ThreatActorCardVulnerability,
    ThreatActorIntelCard,
    ThreatActorIntelCardPage,
)

router = APIRouter(tags=["intel cards"])

THREAT_ACTOR_CARD_PAGE_QUERY = text("""
    SELECT
        actor_id,
        canonical_name,
        entity_classification,
        actor_status,
        sophistication,
        resource_level,
        first_seen,
        last_seen,
        last_seen_raw
    FROM public.threat_actor
    ORDER BY canonical_name, actor_id
    LIMIT :limit OFFSET :offset
""")
THREAT_ACTOR_CARD_COUNT_QUERY = text("SELECT COUNT(*) FROM public.threat_actor")

ALIASES_QUERY = text("""
    SELECT actor_id, alias_name
    FROM public.ta_alias
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_alias_id
""")
DESCRIPTIONS_QUERY = text("""
    SELECT actor_id, description
    FROM public.ta_description
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_description_id
""")
ACTOR_TYPES_QUERY = text("""
    SELECT actor_id, actor_type
    FROM public.ta_actor_type
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_actor_type_id
""")
ROLES_QUERY = text("""
    SELECT actor_id, role
    FROM public.ta_role
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_role_id
""")
MOTIVATIONS_QUERY = text("""
    SELECT actor_id, motivation_category, type
    FROM public.ta_motivation
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_motivation_id
""")
GOALS_QUERY = text("""
    SELECT actor_id, goal
    FROM public.ta_goal
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_goal_id
""")
NEXUS_QUERY = text("""
    SELECT actor_id, country_or_region, relationship
    FROM public.ta_nexus
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_nexus_id
""")
TARGETING_QUERY = text("""
    SELECT actor_id, sector, country, region
    FROM public.ta_targeting
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_targeting_id
""")
TARGETED_ASSETS_QUERY = text("""
    SELECT actor_id, asset_name, environment
    FROM public.ta_targeted_asset
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_targeted_asset_id
""")
TIMELINE_QUERY = text("""
    SELECT actor_id, date, date_end, precision, event_type, event, campaign
    FROM public.ta_timeline
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_timeline_id
""")
EXECUTION_PATHS_QUERY = text("""
    SELECT actor_id, path_id, campaign, date_start, date_end, target_context
    FROM public.ta_execution_path
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_execution_path_id
""")
EXECUTION_STEPS_QUERY = text("""
    SELECT
        actor_id,
        path_id,
        step,
        action,
        behavior_categories,
        malware,
        tools,
        vulnerabilities,
        infrastructure,
        artifacts
    FROM public.ta_execution_step
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY path_id NULLS LAST, step, ta_execution_step_id
""")
CAPABILITIES_QUERY = text("""
    SELECT actor_id, malware_name AS name, 'MALWARE' AS type, relationship, role,
           ta_malware_relationship_id AS row_id
    FROM public.ta_malware_relationship
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    UNION ALL
    SELECT actor_id, tool_name AS name, classification AS type, relationship, role,
           ta_tool_relationship_id AS row_id
    FROM public.ta_tool_relationship
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY actor_id, row_id
""")
INFRASTRUCTURE_QUERY = text("""
    SELECT
        actor_id,
        infrastructure_value,
        infrastructure_type,
        role,
        protocol,
        port,
        hosting_or_service
    FROM public.ta_infrastructure
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_infrastructure_id
""")
VULNERABILITIES_QUERY = text("""
    SELECT actor_id, cve, product, relationship, role
    FROM public.ta_vulnerability
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_vulnerability_id
""")
TTPS_QUERY = text("""
    SELECT actor_id, tactic, technique_id, technique_name, procedure
    FROM public.ta_mitre_attack
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY tactic, technique_id, ta_mitre_attack_id
""")
IOCS_QUERY = text("""
    SELECT
        actor_id,
        indicator_type,
        indicator_value,
        hash_algorithm,
        role,
        context,
        first_seen,
        last_seen
    FROM public.ta_indicator
    WHERE actor_id = ANY(CAST(:actor_ids AS BIGINT[]))
    ORDER BY ta_indicator_id
""")


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _split_values(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    return [item.strip() for item in re.split(r"[;,]", value) if item.strip()]


def _rows_by_actor(rows: list[dict[str, Any]]) -> defaultdict[int, list[dict[str, Any]]]:
    grouped_rows: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        actor_id = row.get("actor_id")
        if isinstance(actor_id, int):
            grouped_rows[actor_id].append(row)
    return grouped_rows


async def _fetch_rows(
    session: AsyncSession,
    query: TextClause,
    actor_ids: list[int],
) -> list[dict[str, Any]]:
    result = await session.execute(query, {"actor_ids": actor_ids})
    return [dict(row) for row in result.mappings()]


def _unique_values(rows: list[dict[str, Any]], key: str) -> list[str]:
    return list(dict.fromkeys(value for row in rows if (value := _as_str(row.get(key)))))


def _execution_step(row: dict[str, Any]) -> ThreatActorCardExecutionStep:
    action = _as_str(row.get("action"))
    step = row.get("step")
    return ThreatActorCardExecutionStep(
        step=step if isinstance(step, int) else None,
        title=action or "",
        action=action,
        categories=_split_values(row.get("behavior_categories")),
        malware=_split_values(row.get("malware")),
        tools=_split_values(row.get("tools")),
        vulnerabilities=_split_values(row.get("vulnerabilities")),
        infrastructure=_split_values(row.get("infrastructure")),
        artifacts=_split_values(row.get("artifacts")),
    )


def _confirmed_paths(
    path_rows: list[dict[str, Any]],
    step_rows: list[dict[str, Any]],
) -> list[ThreatActorCardExecutionPath]:
    steps_by_path: defaultdict[str, list[ThreatActorCardExecutionStep]] = defaultdict(list)
    for row in step_rows:
        path_id = _as_str(row.get("path_id"))
        if path_id:
            steps_by_path[path_id].append(_execution_step(row))
    return [
        ThreatActorCardExecutionPath(
            campaign=_as_str(row.get("campaign")),
            date_start=_as_str(row.get("date_start")),
            date_end=_as_str(row.get("date_end")),
            target_context=_as_str(row.get("target_context")),
            steps=steps_by_path[path_id],
        )
        for row in path_rows
        if (path_id := _as_str(row.get("path_id")))
    ]


@router.get("/threat-actor-reports", response_model=ThreatActorIntelCardPage)
async def list_threat_actor_intel_cards(
    session: Annotated[AsyncSession, Depends(get_database_session)],
    page: Annotated[int, Query(ge=1, description="One-based page number.")] = 1,
) -> ThreatActorIntelCardPage:
    """Return nine complete threat-actor intelligence cards per page."""
    try:
        total_items = (await session.execute(THREAT_ACTOR_CARD_COUNT_QUERY)).scalar_one()
        total_pages = ceil(total_items / MALWARE_CARDS_PER_PAGE) if total_items else 0
        if total_pages and page > total_pages:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Page {page} does not exist. The last available page is {total_pages}.",
            )
        result = await session.execute(
            THREAT_ACTOR_CARD_PAGE_QUERY,
            {"limit": MALWARE_CARDS_PER_PAGE, "offset": (page - 1) * MALWARE_CARDS_PER_PAGE},
        )
        main_rows = [dict(row) for row in result.mappings()]
        actor_ids = [row["actor_id"] for row in main_rows if isinstance(row.get("actor_id"), int)]
        if not actor_ids:
            return ThreatActorIntelCardPage(
                pagination=MalwareCardPagination(
                    page=page,
                    page_size=MALWARE_CARDS_PER_PAGE,
                    total_items=total_items,
                    total_pages=total_pages,
                ),
                items=[],
            )
        queries = (
            ALIASES_QUERY,
            DESCRIPTIONS_QUERY,
            ACTOR_TYPES_QUERY,
            ROLES_QUERY,
            MOTIVATIONS_QUERY,
            GOALS_QUERY,
            NEXUS_QUERY,
            TARGETING_QUERY,
            TARGETED_ASSETS_QUERY,
            TIMELINE_QUERY,
            EXECUTION_PATHS_QUERY,
            EXECUTION_STEPS_QUERY,
            CAPABILITIES_QUERY,
            INFRASTRUCTURE_QUERY,
            VULNERABILITIES_QUERY,
            TTPS_QUERY,
            IOCS_QUERY,
        )
        query_results = [await _fetch_rows(session, query, actor_ids) for query in queries]
    except HTTPException:
        raise
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat-actor intelligence reports are temporarily unavailable.",
        ) from error

    (
        alias_rows,
        description_rows,
        actor_type_rows,
        role_rows,
        motivation_rows,
        goal_rows,
        nexus_rows,
        targeting_rows,
        targeted_asset_rows,
        timeline_rows,
        execution_path_rows,
        execution_step_rows,
        capability_rows,
        infrastructure_rows,
        vulnerability_rows,
        ttp_rows,
        ioc_rows,
    ) = (_rows_by_actor(rows) for rows in query_results)

    items: list[ThreatActorIntelCard] = []
    for row in main_rows:
        actor_id = row.get("actor_id")
        name = _as_str(row.get("canonical_name"))
        if not isinstance(actor_id, int) or not name:
            continue
        actor_motivations = motivation_rows[actor_id]
        primary_motivation = next(
            (
                _as_str(item.get("type"))
                for item in actor_motivations
                if _as_str(item.get("motivation_category")) == "PRIMARY"
            ),
            None,
        )
        actor_targeting = targeting_rows[actor_id]
        targeting = []
        if actor_targeting:
            targeting.append(
                ThreatActorCardTargeting(
                    sectors=_unique_values(actor_targeting, "sector"),
                    countries=_unique_values(actor_targeting, "country"),
                    regions=_unique_values(actor_targeting, "region"),
                )
            )
        actor_steps = execution_step_rows[actor_id]
        items.append(
            ThreatActorIntelCard(
                actor_id=actor_id,
                name=name,
                aliases=_unique_values(alias_rows[actor_id], "alias_name"),
                summary=ThreatActorCardSummary(
                    classification=_as_str(row.get("entity_classification")),
                    status=_as_str(row.get("actor_status")),
                    actor_types=_unique_values(actor_type_rows[actor_id], "actor_type"),
                    roles=_unique_values(role_rows[actor_id], "role"),
                    sophistication=_as_str(row.get("sophistication")),
                    resource_level=_as_str(row.get("resource_level")),
                    primary_motivation=ThreatActorCardMotivation(type=primary_motivation),
                    goals=_unique_values(goal_rows[actor_id], "goal"),
                    first_seen=ThreatActorCardDate(date=_as_str(row.get("first_seen"))),
                    last_seen=ThreatActorCardLastSeen(
                        date=_as_str(row.get("last_seen")),
                        raw_value=_as_str(row.get("last_seen_raw")),
                    ),
                    nexus=[
                        ThreatActorCardNexus(
                            country_or_region=_as_str(item.get("country_or_region")),
                            relationship=_as_str(item.get("relationship")),
                        )
                        for item in nexus_rows[actor_id]
                    ],
                    targeting=targeting,
                    targeted_assets=[
                        ThreatActorCardTargetedAsset(
                            name=_as_str(item.get("asset_name")),
                            environment=_as_str(item.get("environment")),
                        )
                        for item in targeted_asset_rows[actor_id]
                    ],
                ),
                description="\n\n".join(_unique_values(description_rows[actor_id], "description"))
                or None,
                activity_timeline=[
                    ThreatActorCardTimelineItem(
                        date=_as_str(item.get("date")),
                        date_end=_as_str(item.get("date_end")),
                        precision=_as_str(item.get("precision")),
                        event_type=_as_str(item.get("event_type")),
                        event=_as_str(item.get("event")) or "",
                        campaign=_as_str(item.get("campaign")),
                    )
                    for item in timeline_rows[actor_id]
                    if _as_str(item.get("event"))
                ],
                execution=ThreatActorCardExecution(
                    confirmed_paths=_confirmed_paths(execution_path_rows[actor_id], actor_steps),
                    observed_activities=[
                        ThreatActorCardObservedActivity(
                            activity=_as_str(item.get("action")) or "",
                            categories=_split_values(item.get("behavior_categories")),
                            campaign=None,
                            malware=_split_values(item.get("malware")),
                            tools=_split_values(item.get("tools")),
                            vulnerabilities=_split_values(item.get("vulnerabilities")),
                            infrastructure=_split_values(item.get("infrastructure")),
                            artifacts=_split_values(item.get("artifacts")),
                        )
                        for item in actor_steps
                        if not _as_str(item.get("path_id")) and _as_str(item.get("action"))
                    ],
                ),
                capabilities=[
                    ThreatActorCardCapability(
                        name=_as_str(item.get("name")) or "",
                        type=_as_str(item.get("type")),
                        relationship=_as_str(item.get("relationship")),
                        role=_as_str(item.get("role")),
                    )
                    for item in capability_rows[actor_id]
                    if _as_str(item.get("name"))
                ],
                infrastructure=[
                    ThreatActorCardInfrastructure(
                        value=_as_str(item.get("infrastructure_value")) or "",
                        type=_as_str(item.get("infrastructure_type")),
                        role=_as_str(item.get("role")),
                        protocol=_as_str(item.get("protocol")),
                        port=_as_str(item.get("port")),
                        service=_as_str(item.get("hosting_or_service")),
                    )
                    for item in infrastructure_rows[actor_id]
                    if _as_str(item.get("infrastructure_value"))
                ],
                vulnerabilities=[
                    ThreatActorCardVulnerability(
                        cve=_as_str(item.get("cve")),
                        product=_as_str(item.get("product")),
                        relationship=_as_str(item.get("relationship")),
                        role=_as_str(item.get("role")),
                    )
                    for item in vulnerability_rows[actor_id]
                ],
                ttps=[
                    ThreatActorCardTtp(
                        tactic=_as_str(item.get("tactic")),
                        technique_id=_as_str(item.get("technique_id")),
                        technique=_as_str(item.get("technique_name")),
                        procedure=_as_str(item.get("procedure")),
                    )
                    for item in ttp_rows[actor_id]
                ],
                iocs=[
                    ThreatActorCardIoc(
                        type=_as_str(item.get("indicator_type")),
                        value=_as_str(item.get("indicator_value")) or "",
                        hash_algorithm=_as_str(item.get("hash_algorithm")),
                        role=_as_str(item.get("role")),
                        context=_as_str(item.get("context")),
                        first_seen=_as_str(item.get("first_seen")),
                        last_seen=_as_str(item.get("last_seen")),
                    )
                    for item in ioc_rows[actor_id]
                    if _as_str(item.get("indicator_value"))
                ],
            )
        )

    return ThreatActorIntelCardPage(
        pagination=MalwareCardPagination(
            page=page,
            page_size=MALWARE_CARDS_PER_PAGE,
            total_items=total_items,
            total_pages=total_pages,
        ),
        items=items,
    )
