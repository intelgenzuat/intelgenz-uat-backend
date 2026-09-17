"""Threat-actor discovery and ATT&CK mapping endpoints."""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from intelgenz_api.core.d3fend import D3fendTechniqueContext, get_attack_d3fend_index
from intelgenz_api.core.database import get_database_session
from intelgenz_api.core.mitre_attack import MitreTechniqueContext, get_mitre_technique_index
from intelgenz_api.core.nist import get_d3fend_nist_index, get_nist_control_family_index
from intelgenz_api.modules.threat_actor_profiling.schemas import (
    TechniqueSearchItem,
    TechniqueSearchResponse,
    ThreatActorAttackTechniqueDefenseSource,
    ThreatActorCioAssessmentResponse,
    ThreatActorCioItem,
    ThreatActorD3fendTacticMapping,
    ThreatActorD3fendTechniqueMappingItem,
    ThreatActorMappingRequest,
    ThreatActorMappingResponse,
    ThreatActorNistControlFamilyMapping,
    ThreatActorNistControlMappingItem,
    ThreatActorNistD3fendSource,
    ThreatActorSearchItem,
    ThreatActorSearchResponse,
    ThreatActorTacticTechniqueMapping,
    ThreatActorTechniqueCioItem,
    ThreatActorTechniqueCioResponse,
    ThreatActorTechniqueMappingItem,
    ThreatActorUsingTechnique,
)

router = APIRouter()

THREAT_ACTOR_SEARCH_QUERY = text("""
    SELECT
        threat_actor.actor_id,
        threat_actor.canonical_name AS name
    FROM threat_actor
    WHERE threat_actor.canonical_name ILIKE :contains_query
       OR EXISTS (
           SELECT 1
           FROM ta_alias
           WHERE ta_alias.actor_id = threat_actor.actor_id
             AND ta_alias.alias_name ILIKE :contains_query
       )
       OR EXISTS (
           SELECT 1
           FROM ta_similar_name
           WHERE ta_similar_name.actor_id = threat_actor.actor_id
             AND ta_similar_name.similar_name ILIKE :contains_query
       )
    ORDER BY
        CASE
            WHEN LOWER(threat_actor.canonical_name) = LOWER(:query) THEN 0
            WHEN LOWER(threat_actor.canonical_name) LIKE LOWER(:prefix_query) THEN 1
            ELSE 2
        END,
        threat_actor.canonical_name
    LIMIT :limit
""")

MITRE_TECHNIQUE_ID_SEARCH_QUERY = text("""
    SELECT technique_id, name
    FROM public.mitre_technique_ids
    WHERE technique_id LIKE :prefix_query
    ORDER BY
        CASE WHEN technique_id = :query THEN 0 ELSE 1 END,
        technique_id
    LIMIT :limit
""")

THREAT_ACTOR_TECHNIQUE_QUERY = text("""
    WITH selected_actors AS (
        SELECT actor_id, position
        FROM unnest(CAST(:actor_ids AS BIGINT[])) WITH ORDINALITY
            AS selected(actor_id, position)
    )
    SELECT DISTINCT
        selected_actors.position,
        selected_actors.actor_id,
        threat_actor.canonical_name AS actor_name,
        ta_mitre_attack.technique_id
    FROM selected_actors
    JOIN threat_actor ON threat_actor.actor_id = selected_actors.actor_id
    JOIN ta_mitre_attack ON ta_mitre_attack.actor_id = selected_actors.actor_id
    WHERE ta_mitre_attack.technique_id IS NOT NULL
      AND ta_mitre_attack.technique_id <> ''
    ORDER BY selected_actors.position, ta_mitre_attack.technique_id
""")

THREAT_ACTOR_ALL_TECHNIQUES_CIO_QUERY = text("""
    WITH requested_techniques AS (
        SELECT DISTINCT technique_id
        FROM unnest(CAST(:technique_ids AS TEXT[])) AS requested(technique_id)
    ),
    matched_actors AS (
        SELECT ta_mitre_attack.actor_id
        FROM public.ta_mitre_attack
        JOIN requested_techniques
            ON requested_techniques.technique_id = ta_mitre_attack.technique_id
        GROUP BY ta_mitre_attack.actor_id
        HAVING COUNT(DISTINCT ta_mitre_attack.technique_id) = :technique_count
    )
    SELECT
        threat_actor.actor_id,
        threat_actor.canonical_name AS name,
        COALESCE(LOWER(threat_actor_cio_curation_summary.capability), '') = 'yes' AS capability,
        COALESCE(LOWER(threat_actor_cio_curation_summary.intent), '') = 'yes' AS intent,
        COALESCE(LOWER(threat_actor_cio_curation_summary.opportunity), '') = 'yes' AS opportunity
    FROM matched_actors
    JOIN public.threat_actor
        ON threat_actor.actor_id = matched_actors.actor_id
    JOIN public.threat_actor_cio_curation_summary
        ON threat_actor_cio_curation_summary.actor_id = matched_actors.actor_id
       AND threat_actor_cio_curation_summary.client_name = :client_name
    WHERE (COALESCE(LOWER(threat_actor_cio_curation_summary.capability), '') = 'yes') = :capability
      AND (COALESCE(LOWER(threat_actor_cio_curation_summary.intent), '') = 'yes') = :intent
      AND (
          COALESCE(LOWER(threat_actor_cio_curation_summary.opportunity), '') = 'yes'
      ) = :opportunity
    ORDER BY threat_actor.canonical_name, threat_actor.actor_id
""")

THREAT_ACTOR_CIO_ASSESSMENT_QUERY = text("""
    SELECT
        threat_actor.actor_id,
        threat_actor.canonical_name AS name,
        COALESCE(LOWER(threat_actor_cio_curation_summary.capability), '') = 'yes' AS capability,
        COALESCE(LOWER(threat_actor_cio_curation_summary.intent), '') = 'yes' AS intent,
        COALESCE(LOWER(threat_actor_cio_curation_summary.opportunity), '') = 'yes' AS opportunity
    FROM public.threat_actor_cio_curation_summary
    JOIN public.threat_actor
        ON threat_actor.actor_id = threat_actor_cio_curation_summary.actor_id
    WHERE threat_actor_cio_curation_summary.client_name = :client_name
      AND (COALESCE(LOWER(threat_actor_cio_curation_summary.capability), '') = 'yes') = :capability
      AND (COALESCE(LOWER(threat_actor_cio_curation_summary.intent), '') = 'yes') = :intent
      AND (
          COALESCE(LOWER(threat_actor_cio_curation_summary.opportunity), '') = 'yes'
      ) = :opportunity
    ORDER BY threat_actor.canonical_name, threat_actor.actor_id
""")

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

D3FEND_TACTIC_ORDER = {
    "Model": 0,
    "Harden": 1,
    "Detect": 2,
    "Isolate": 3,
    "Deceive": 4,
    "Evict": 5,
    "Restore": 6,
}


@dataclass
class D3fendTechniqueUsage:
    context: D3fendTechniqueContext
    actors: dict[int, str] = field(default_factory=dict)
    actors_by_attack_technique: defaultdict[str, dict[int, str]] = field(
        default_factory=lambda: defaultdict(dict)
    )


@dataclass
class NistControlUsage:
    catalog: str
    control_id: str
    relations: set[str] = field(default_factory=set)
    actors: dict[int, str] = field(default_factory=dict)
    d3fend_techniques: dict[str, D3fendTechniqueUsage] = field(default_factory=dict)


def _actor_references(actors: dict[int, str]) -> list[ThreatActorUsingTechnique]:
    """Return actor references in the selection order preserved by the query."""
    return [
        ThreatActorUsingTechnique(actor_id=actor_id, name=name) for actor_id, name in actors.items()
    ]


def _overlap_percentage(overlap_count: int, selected_actor_count: int) -> int:
    """Treat techniques used by only one selected actor as no overlap."""
    return round(100 * overlap_count / selected_actor_count) if overlap_count > 1 else 0


def _normalize_client_name(client_name: str) -> str:
    """Normalize and validate a client profile name."""
    normalized_client_name = client_name.strip().upper()
    if not normalized_client_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="client_name must contain at least one non-space character.",
        )
    return normalized_client_name


def _parse_technique_ids(technique_ids: list[str]) -> list[str]:
    """Normalize repeated ATT&CK technique query parameters in input order."""
    normalized_ids = [
        technique_id.strip().upper() for technique_id in technique_ids if technique_id.strip()
    ]
    if not normalized_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="technique_ids must contain at least one technique ID.",
        )
    if len(normalized_ids) != len(set(normalized_ids)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="technique_ids must not contain duplicates.",
        )
    if len(normalized_ids) > 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="A maximum of 50 technique IDs is allowed.",
        )
    invalid_ids = [
        technique_id
        for technique_id in normalized_ids
        if not TECHNIQUE_ID_PATTERN.fullmatch(technique_id)
    ]
    if invalid_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid ATT&CK technique IDs: {', '.join(invalid_ids)}.",
        )
    return normalized_ids


@router.get("/search", response_model=ThreatActorSearchResponse, tags=["TTP Mitigation"])
async def search_threat_actors(
    query: Annotated[
        str,
        Query(min_length=2, max_length=100, description="At least two characters."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> ThreatActorSearchResponse:
    """Return threat-actor suggestions matching canonical, alias, or similar names."""
    normalized_query = query.strip()
    if len(normalized_query) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Query must contain at least two non-space characters.",
        )

    try:
        result = await session.execute(
            THREAT_ACTOR_SEARCH_QUERY,
            {
                "query": normalized_query,
                "prefix_query": f"{normalized_query}%",
                "contains_query": f"%{normalized_query}%",
                "limit": limit,
            },
        )
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat-actor search is temporarily unavailable.",
        ) from error

    return ThreatActorSearchResponse(
        query=normalized_query,
        results=[
            ThreatActorSearchItem(actor_id=row["actor_id"], name=row["name"])
            for row in result.mappings()
        ],
    )


@router.get(
    "/techniques/search",
    response_model=TechniqueSearchResponse,
    tags=["Threat Actor Profiling"],
)
async def search_mitre_technique_ids(
    query: Annotated[
        str,
        Query(min_length=3, max_length=20, description="At least three ID characters."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> TechniqueSearchResponse:
    """Return lightweight ATT&CK technique and sub-technique ID suggestions."""
    normalized_query = query.strip().upper()
    if len(normalized_query) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Query must contain at least three non-space characters.",
        )

    try:
        result = await session.execute(
            MITRE_TECHNIQUE_ID_SEARCH_QUERY,
            {
                "query": normalized_query,
                "prefix_query": f"{normalized_query}%",
                "limit": limit,
            },
        )
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MITRE technique search is temporarily unavailable.",
        ) from error

    return TechniqueSearchResponse(
        items=[
            TechniqueSearchItem(technique_id=row["technique_id"], name=row["name"])
            for row in result.mappings()
        ]
    )


@router.get(
    "/by-assessment",
    response_model=ThreatActorCioAssessmentResponse,
    tags=["Threat Actor Profiling"],
)
async def find_threat_actors_by_assessment(
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name for CIO assessment."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
    capability: Annotated[bool, Query(description="Required Capability value.")] = True,
    intent: Annotated[bool, Query(description="Required Intent value.")] = True,
    opportunity: Annotated[bool, Query(description="Required Opportunity value.")] = True,
) -> ThreatActorCioAssessmentResponse:
    """Find client-assessed actors matching the exact CIO true/false combination."""
    normalized_client_name = _normalize_client_name(client_name)
    try:
        result = await session.execute(
            THREAT_ACTOR_CIO_ASSESSMENT_QUERY,
            {
                "client_name": normalized_client_name,
                "capability": capability,
                "intent": intent,
                "opportunity": opportunity,
            },
        )
        rows = list(result.mappings())
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat actor profiling is temporarily unavailable.",
        ) from error

    return ThreatActorCioAssessmentResponse(
        client_name=normalized_client_name,
        capability=capability,
        intent=intent,
        opportunity=opportunity,
        matched_actor_count=len(rows),
        actors=[
            ThreatActorCioItem(
                actor_id=row["actor_id"],
                name=row["name"],
                capability=row["capability"],
                intent=row["intent"],
                opportunity=row["opportunity"],
            )
            for row in rows
        ],
    )


@router.get(
    "/by-techniques",
    response_model=ThreatActorTechniqueCioResponse,
    tags=["Threat Actor Profiling"],
)
async def find_threat_actors_by_techniques(
    technique_ids: Annotated[
        list[str],
        Query(
            min_length=1,
            max_length=50,
            description=(
                "Repeat technique_ids for each ATT&CK ID. Actors must use every supplied ID."
            ),
        ),
    ],
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client profile name for CIO assessment."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
    capability: Annotated[bool, Query(description="Required Capability value.")] = True,
    intent: Annotated[bool, Query(description="Required Intent value.")] = True,
    opportunity: Annotated[bool, Query(description="Required Opportunity value.")] = True,
) -> ThreatActorTechniqueCioResponse:
    """Find client-assessed actors that use every requested ATT&CK technique."""
    requested_technique_ids = _parse_technique_ids(technique_ids)
    normalized_client_name = _normalize_client_name(client_name)
    try:
        result = await session.execute(
            THREAT_ACTOR_ALL_TECHNIQUES_CIO_QUERY,
            {
                "technique_ids": requested_technique_ids,
                "technique_count": len(requested_technique_ids),
                "client_name": normalized_client_name,
                "capability": capability,
                "intent": intent,
                "opportunity": opportunity,
            },
        )
        rows = list(result.mappings())
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat actor technique matching is temporarily unavailable.",
        ) from error

    return ThreatActorTechniqueCioResponse(
        client_name=normalized_client_name,
        requested_technique_ids=requested_technique_ids,
        matched_actor_count=len(rows),
        actors=[
            ThreatActorTechniqueCioItem(
                actor_id=row["actor_id"],
                name=row["name"],
                matched_technique_ids=requested_technique_ids,
                capability=row["capability"],
                intent=row["intent"],
                opportunity=row["opportunity"],
            )
            for row in rows
        ],
    )


@router.post("/mapping", response_model=ThreatActorMappingResponse, tags=["TTP Mitigation"])
async def get_threat_actor_mapping(
    payload: ThreatActorMappingRequest,
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> ThreatActorMappingResponse:
    """Map selected threat actors through ATT&CK, D3FEND, and NIST controls."""
    try:
        result = await session.execute(
            THREAT_ACTOR_TECHNIQUE_QUERY,
            {"actor_ids": payload.actor_ids},
        )
        mitre_technique_index = get_mitre_technique_index()
        d3fend_technique_index = get_attack_d3fend_index()
        nist_control_index = get_d3fend_nist_index()
        nist_family_index = get_nist_control_family_index()
    except (OSError, SQLAlchemyError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat-actor, ATT&CK, D3FEND, or NIST data is unavailable.",
        ) from error

    actors_by_attack_technique: defaultdict[str, dict[int, str]] = defaultdict(dict)
    for row in result.mappings():
        technique_id = row["technique_id"]
        if technique_id in mitre_technique_index:
            actors_by_attack_technique[technique_id][row["actor_id"]] = row["actor_name"]

    actors_by_mitre_context: defaultdict[MitreTechniqueContext, dict[int, str]] = defaultdict(dict)
    for technique_id, actors in actors_by_attack_technique.items():
        for context in mitre_technique_index[technique_id]:
            actors_by_mitre_context[context].update(actors)

    tactics_by_name: defaultdict[str, list[ThreatActorTechniqueMappingItem]] = defaultdict(list)
    tactic_order: dict[str, int] = {}
    for context in sorted(
        actors_by_mitre_context,
        key=lambda item: (item.tactic_order, item.technique_name, item.subtechnique_name or ""),
    ):
        actors = actors_by_mitre_context[context]
        overlap_count = len(actors)
        tactic_order[context.tactic_name] = context.tactic_order
        tactics_by_name[context.tactic_name].append(
            ThreatActorTechniqueMappingItem(
                technique_id=context.technique_id,
                technique_name=context.technique_name,
                subtechnique_name=context.subtechnique_name,
                overlap_count=overlap_count,
                overlap_percentage=_overlap_percentage(overlap_count, len(payload.actor_ids)),
                has_overlap=overlap_count > 1,
                actors=_actor_references(actors),
            )
        )

    d3fend_usage_by_id: dict[str, D3fendTechniqueUsage] = {}
    for attack_technique_id, actors in actors_by_attack_technique.items():
        for d3fend_context in d3fend_technique_index.get(attack_technique_id, ()):
            usage = d3fend_usage_by_id.setdefault(
                d3fend_context.d3fend_id,
                D3fendTechniqueUsage(context=d3fend_context),
            )
            usage.actors.update(actors)
            usage.actors_by_attack_technique[attack_technique_id].update(actors)

    d3fend_by_tactic: defaultdict[str, list[ThreatActorD3fendTechniqueMappingItem]] = defaultdict(
        list
    )
    for usage in sorted(d3fend_usage_by_id.values(), key=lambda item: item.context.name):
        attack_techniques = []
        for attack_technique_id, actors in sorted(usage.actors_by_attack_technique.items()):
            contexts = mitre_technique_index[attack_technique_id]
            first_context = contexts[0]
            attack_techniques.append(
                ThreatActorAttackTechniqueDefenseSource(
                    technique_id=attack_technique_id,
                    technique_name=first_context.technique_name,
                    subtechnique_name=first_context.subtechnique_name,
                    tactics=sorted({context.tactic_name for context in contexts}),
                    actors=_actor_references(actors),
                )
            )

        overlap_count = len(usage.actors)
        item = ThreatActorD3fendTechniqueMappingItem(
            d3fend_id=usage.context.d3fend_id,
            name=usage.context.name,
            parent_technique=usage.context.parent_technique,
            overlap_count=overlap_count,
            overlap_percentage=_overlap_percentage(overlap_count, len(payload.actor_ids)),
            has_overlap=overlap_count > 1,
            actors=_actor_references(usage.actors),
            attack_techniques=attack_techniques,
        )
        for tactic_name in usage.context.tactics:
            d3fend_by_tactic[tactic_name].append(item)

    nist_usage_by_control: dict[str, NistControlUsage] = {}
    for attack_technique_id, actors in actors_by_attack_technique.items():
        for d3fend_context in d3fend_technique_index.get(attack_technique_id, ()):
            for nist_context in nist_control_index.get(d3fend_context.name, ()):
                nist_usage = nist_usage_by_control.setdefault(
                    nist_context.control_id,
                    NistControlUsage(
                        catalog=nist_context.catalog,
                        control_id=nist_context.control_id,
                    ),
                )
                nist_usage.relations.add(nist_context.relation)
                nist_usage.actors.update(actors)
                d3fend_usage = nist_usage.d3fend_techniques.setdefault(
                    d3fend_context.d3fend_id,
                    D3fendTechniqueUsage(context=d3fend_context),
                )
                d3fend_usage.actors.update(actors)
                d3fend_usage.actors_by_attack_technique[attack_technique_id].update(actors)

    controls_by_family: defaultdict[str, list[ThreatActorNistControlMappingItem]] = defaultdict(
        list
    )
    for nist_usage in sorted(nist_usage_by_control.values(), key=lambda item: item.control_id):
        family_id = nist_usage.control_id.split("-", maxsplit=1)[0]
        overlap_count = len(nist_usage.actors)
        controls_by_family[family_id].append(
            ThreatActorNistControlMappingItem(
                catalog=nist_usage.catalog,
                control_id=nist_usage.control_id,
                relations=sorted(nist_usage.relations),
                overlap_count=overlap_count,
                overlap_percentage=_overlap_percentage(overlap_count, len(payload.actor_ids)),
                has_overlap=overlap_count > 1,
                actors=_actor_references(nist_usage.actors),
                d3fend_techniques=[
                    ThreatActorNistD3fendSource(
                        d3fend_id=source.context.d3fend_id,
                        name=source.context.name,
                        attack_technique_ids=sorted(source.actors_by_attack_technique),
                    )
                    for source in sorted(
                        nist_usage.d3fend_techniques.values(),
                        key=lambda item: item.context.d3fend_id,
                    )
                ],
            )
        )

    return ThreatActorMappingResponse(
        selected_actor_count=len(payload.actor_ids),
        tactics=[
            ThreatActorTacticTechniqueMapping(
                tactic_name=tactic_name,
                techniques=tactics_by_name[tactic_name],
            )
            for tactic_name in sorted(tactics_by_name, key=lambda item: tactic_order[item])
        ],
        d3fend_tactics=[
            ThreatActorD3fendTacticMapping(
                tactic_name=tactic_name,
                techniques=d3fend_by_tactic[tactic_name],
            )
            for tactic_name in sorted(
                d3fend_by_tactic,
                key=lambda item: (D3FEND_TACTIC_ORDER.get(item, len(D3FEND_TACTIC_ORDER)), item),
            )
        ],
        nist_control_families=[
            ThreatActorNistControlFamilyMapping(
                family_id=family_id,
                family_name=nist_family_index.get(family_id, family_id),
                controls=controls,
            )
            for family_id, controls in sorted(controls_by_family.items())
        ],
    )
