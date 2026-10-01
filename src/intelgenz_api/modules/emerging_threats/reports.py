"""Client-scoped emerging threat report list and detail endpoints."""

from math import ceil
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from intelgenz_api.core.database import get_database_session
from intelgenz_api.modules.emerging_threats.schemas import (
    EmergingThreatReportDetail,
    EmergingThreatReportListItem,
    EmergingThreatReportListPage,
    EmergingThreatReportSection,
    EtrActivityPeriod,
    EtrTargeting,
)

router = APIRouter()

ETR_REPORTS_PER_PAGE = 6

ETR_REPORT_LIST_QUERY = text("""
    SELECT
        report.report_id,
        report.report_title AS title,
        report.report_subtitle AS subtitle,
        report.actor_name,
        report.report_type,
        report.curation,
        report.activity_period_start,
        report.activity_period_end,
        report.activity_period_description,
        impact.severity,
        ARRAY(
            SELECT region
            FROM public.etr_section_affected_region
            WHERE section_id = impact.section_id
            ORDER BY ordinal
        ) AS regions,
        ARRAY(
            SELECT country
            FROM public.etr_section_affected_country
            WHERE section_id = impact.section_id
            ORDER BY ordinal
        ) AS countries,
        ARRAY(
            SELECT sector
            FROM public.etr_section_affected_sector
            WHERE section_id = impact.section_id
            ORDER BY ordinal
        ) AS sectors
    FROM public.etr_client AS client
    JOIN public.etr_report AS report ON report.report_id = client.report_id
    LEFT JOIN LATERAL (
        SELECT section_id, severity
        FROM public.etr_section
        WHERE report_id = report.report_id
          AND section_type = 'impact_overview'
        ORDER BY ordinal
        LIMIT 1
    ) AS impact ON TRUE
    WHERE client.client_name = :client_name
    ORDER BY
        COALESCE(NULLIF(report.activity_period_end, ''), NULLIF(report.activity_period_start, ''))
            DESC NULLS LAST,
        report.report_id DESC
    LIMIT :limit OFFSET :offset
""")

ETR_REPORT_LIST_COUNT_QUERY = text("""
    SELECT COUNT(*)
    FROM public.etr_client
    WHERE client_name = :client_name
""")

ETR_REPORT_HEADER_QUERY = text("""
    SELECT
        report.report_id,
        report.source_file,
        client.client_name,
        report.report_type,
        report.report_title AS title,
        report.report_subtitle AS subtitle,
        report.actor_name,
        report.curation,
        report.activity_period_start,
        report.activity_period_end,
        report.activity_period_description
    FROM public.etr_client AS client
    JOIN public.etr_report AS report ON report.report_id = client.report_id
    WHERE client.client_name = :client_name
      AND report.report_id = :report_id
""")

ETR_SECTIONS_QUERY = text("""
    SELECT section_id, section_type, section_title, impact, severity
    FROM public.etr_section
    WHERE report_id = :report_id
    ORDER BY ordinal, section_id
""")

SECTION_CONTENT_QUERY = text("""
    SELECT section_id, content
    FROM public.etr_section_content
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_SUMMARY_QUERY = text("""
    SELECT section_id, summary
    FROM public.etr_section_summary
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_PLATFORM_QUERY = text("""
    SELECT section_id, platform
    FROM public.etr_section_affected_platform
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_USER_QUERY = text("""
    SELECT section_id, impacted_user
    FROM public.etr_section_impacted_user
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_COUNTRY_QUERY = text("""
    SELECT section_id, country
    FROM public.etr_section_affected_country
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_SECTOR_QUERY = text("""
    SELECT section_id, sector
    FROM public.etr_section_affected_sector
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_REGION_QUERY = text("""
    SELECT section_id, region
    FROM public.etr_section_affected_region
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
SECTION_ITEMS_QUERY = text("""
    SELECT
        section_item_id,
        section_id,
        item_kind,
        item_id,
        item_name,
        item_title,
        procedure,
        scope,
        guidance
    FROM public.etr_section_item
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
ITEM_ADDRESSES_QUERY = text("""
    SELECT section_item_id, address
    FROM public.etr_section_item_address
    WHERE section_item_id = ANY(CAST(:item_ids AS BIGINT[]))
    ORDER BY section_item_id, ordinal
""")
ITEM_GUIDANCE_QUERY = text("""
    SELECT section_item_id, guidance
    FROM public.etr_section_item_guidance
    WHERE section_item_id = ANY(CAST(:item_ids AS BIGINT[]))
    ORDER BY section_item_id, ordinal
""")
ITEM_MAPPINGS_QUERY = text("""
    SELECT section_item_id, framework, mapping_id, mapping_name, rationale
    FROM public.etr_section_item_mapping
    WHERE section_item_id = ANY(CAST(:item_ids AS BIGINT[]))
    ORDER BY section_item_id, ordinal
""")
EXECUTION_PATHS_QUERY = text("""
    SELECT
        execution_path_id,
        section_id,
        path_title,
        campaign,
        coverage_note,
        mermaid,
        period_start,
        period_end
    FROM public.etr_execution_path
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, ordinal
""")
PATH_DESCRIPTIONS_QUERY = text("""
    SELECT execution_path_id, description
    FROM public.etr_execution_path_description
    WHERE execution_path_id = ANY(CAST(:path_ids AS BIGINT[]))
    ORDER BY execution_path_id, ordinal
""")
EXECUTION_STEPS_QUERY = text("""
    SELECT execution_path_id, step_number, action
    FROM public.etr_execution_step
    WHERE execution_path_id = ANY(CAST(:path_ids AS BIGINT[]))
    ORDER BY execution_path_id, ordinal
""")
EXECUTION_TTPS_QUERY = text("""
    SELECT
        execution_ttp_id,
        section_id,
        execution_path_id,
        ttp_group,
        technique_id,
        technique_name,
        procedure,
        scope
    FROM public.etr_execution_ttp
    WHERE section_id = ANY(CAST(:section_ids AS BIGINT[]))
    ORDER BY section_id, execution_path_id NULLS FIRST, ordinal
""")
TTP_STEPS_QUERY = text("""
    SELECT execution_ttp_id, step_number
    FROM public.etr_execution_ttp_step
    WHERE execution_ttp_id = ANY(CAST(:ttp_ids AS BIGINT[]))
    ORDER BY execution_ttp_id, ordinal
""")


def _normalize_client_name(client_name: str) -> str:
    """Validate the client scope used to retrieve ETR reports."""
    normalized_client_name = client_name.strip()
    if not normalized_client_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="client_name must contain at least one non-space character.",
        )
    return normalized_client_name


async def _fetch_rows(
    session: AsyncSession,
    query: Any,
    parameters: dict[str, Any],
) -> list[dict[str, Any]]:
    """Fetch mappings as regular dictionaries for nested response construction."""
    result = await session.execute(query, parameters)
    return [dict(row) for row in result.mappings()]


@router.get("/reports", response_model=EmergingThreatReportListPage)
async def list_emerging_threat_reports(
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client name assigned to the reports."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
    page: Annotated[int, Query(ge=1)] = 1,
) -> EmergingThreatReportListPage:
    """Return six lightweight emerging-threat report cards for one client."""
    normalized_client_name = _normalize_client_name(client_name)
    try:
        total_items = await session.scalar(
            ETR_REPORT_LIST_COUNT_QUERY,
            {"client_name": normalized_client_name},
        )
        rows = await _fetch_rows(
            session,
            ETR_REPORT_LIST_QUERY,
            {
                "client_name": normalized_client_name,
                "limit": ETR_REPORTS_PER_PAGE,
                "offset": (page - 1) * ETR_REPORTS_PER_PAGE,
            },
        )
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Emerging threat reports are temporarily unavailable.",
        ) from error

    return EmergingThreatReportListPage(
        client_name=normalized_client_name,
        page=page,
        total_items=int(total_items or 0),
        total_pages=ceil(int(total_items or 0) / ETR_REPORTS_PER_PAGE) if total_items else 0,
        items=[
            EmergingThreatReportListItem(
                report_id=row["report_id"],
                title=row["title"],
                subtitle=row["subtitle"],
                actor_name=row["actor_name"],
                report_type=row["report_type"],
                curation=row["curation"],
                activity_period=EtrActivityPeriod(
                    start=row["activity_period_start"],
                    end=row["activity_period_end"],
                    description=row["activity_period_description"],
                ),
                targeting=EtrTargeting(
                    regions=row["regions"] or [],
                    countries=row["countries"] or [],
                    sectors=row["sectors"] or [],
                ),
                severity=row["severity"],
            )
            for row in rows
        ],
    )


@router.get("/reports/{report_id}", response_model=EmergingThreatReportDetail)
async def get_emerging_threat_report(
    report_id: int,
    client_name: Annotated[
        str,
        Query(min_length=1, max_length=200, description="Client name assigned to the report."),
    ],
    session: Annotated[AsyncSession, Depends(get_database_session)],
) -> EmergingThreatReportDetail:
    """Return the complete normalized report selected from an emerging-threat card."""
    normalized_client_name = _normalize_client_name(client_name)
    try:
        header_rows = await _fetch_rows(
            session,
            ETR_REPORT_HEADER_QUERY,
            {"client_name": normalized_client_name, "report_id": report_id},
        )
        if not header_rows:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Emerging threat report was not found for this client.",
            )
        header = header_rows[0]
        section_rows = await _fetch_rows(session, ETR_SECTIONS_QUERY, {"report_id": report_id})
        if not section_rows:
            return EmergingThreatReportDetail(
                report_id=header["report_id"],
                source_file=header["source_file"],
                client_name=header["client_name"],
                report_type=header["report_type"],
                title=header["title"],
                subtitle=header["subtitle"],
                actor_name=header["actor_name"],
                curation=header["curation"],
                activity_period=EtrActivityPeriod(
                    start=header["activity_period_start"],
                    end=header["activity_period_end"],
                    description=header["activity_period_description"],
                ),
                sections=[],
            )

        section_ids = [row["section_id"] for row in section_rows]
        sections_by_id: dict[int, dict[str, Any]] = {
            row["section_id"]: {
                "section_type": row["section_type"],
                "title": row["section_title"],
                "content": [],
                "summary": [],
                "impact": row["impact"],
                "severity": row["severity"],
                "affected_platforms": [],
                "impacted_users": [],
                "targeting": {"regions": [], "countries": [], "sectors": []},
                "items": [],
                "execution_paths": [],
                "unplaced_ttps": [],
            }
            for row in section_rows
        }

        for query, field_name, value_name in (
            (SECTION_CONTENT_QUERY, "content", "content"),
            (SECTION_SUMMARY_QUERY, "summary", "summary"),
            (SECTION_PLATFORM_QUERY, "affected_platforms", "platform"),
            (SECTION_USER_QUERY, "impacted_users", "impacted_user"),
        ):
            for row in await _fetch_rows(session, query, {"section_ids": section_ids}):
                if row[value_name]:
                    sections_by_id[row["section_id"]][field_name].append(row[value_name])

        for query, targeting_field, value_name in (
            (SECTION_REGION_QUERY, "regions", "region"),
            (SECTION_COUNTRY_QUERY, "countries", "country"),
            (SECTION_SECTOR_QUERY, "sectors", "sector"),
        ):
            for row in await _fetch_rows(session, query, {"section_ids": section_ids}):
                if row[value_name]:
                    sections_by_id[row["section_id"]]["targeting"][targeting_field].append(
                        row[value_name]
                    )

        item_rows = await _fetch_rows(session, SECTION_ITEMS_QUERY, {"section_ids": section_ids})
        items_by_id: dict[int, dict[str, Any]] = {}
        for row in item_rows:
            item = {
                "item_kind": row["item_kind"],
                "item_id": row["item_id"],
                "item_name": row["item_name"],
                "title": row["item_title"],
                "procedure": row["procedure"],
                "scope": row["scope"],
                "addresses": [],
                "guidance": [row["guidance"]] if row["guidance"] else [],
                "mappings": [],
            }
            items_by_id[row["section_item_id"]] = item
            sections_by_id[row["section_id"]]["items"].append(item)

        if items_by_id:
            item_ids = list(items_by_id)
            for row in await _fetch_rows(session, ITEM_ADDRESSES_QUERY, {"item_ids": item_ids}):
                if row["address"]:
                    items_by_id[row["section_item_id"]]["addresses"].append(row["address"])
            for row in await _fetch_rows(session, ITEM_GUIDANCE_QUERY, {"item_ids": item_ids}):
                if row["guidance"]:
                    items_by_id[row["section_item_id"]]["guidance"].append(row["guidance"])
            for row in await _fetch_rows(session, ITEM_MAPPINGS_QUERY, {"item_ids": item_ids}):
                items_by_id[row["section_item_id"]]["mappings"].append(
                    {
                        "framework": row["framework"],
                        "mapping_id": row["mapping_id"],
                        "mapping_name": row["mapping_name"],
                        "rationale": row["rationale"],
                    }
                )

        path_rows = await _fetch_rows(session, EXECUTION_PATHS_QUERY, {"section_ids": section_ids})
        paths_by_id: dict[int, dict[str, Any]] = {}
        for row in path_rows:
            path = {
                "title": row["path_title"],
                "campaign": row["campaign"],
                "coverage_note": row["coverage_note"],
                "description": [],
                "mermaid": row["mermaid"],
                "activity_period": {
                    "start": row["period_start"],
                    "end": row["period_end"],
                    "description": None,
                },
                "steps": [],
                "ttps": [],
            }
            paths_by_id[row["execution_path_id"]] = path
            sections_by_id[row["section_id"]]["execution_paths"].append(path)

        if paths_by_id:
            path_ids = list(paths_by_id)
            for row in await _fetch_rows(session, PATH_DESCRIPTIONS_QUERY, {"path_ids": path_ids}):
                if row["description"]:
                    paths_by_id[row["execution_path_id"]]["description"].append(row["description"])
            for row in await _fetch_rows(session, EXECUTION_STEPS_QUERY, {"path_ids": path_ids}):
                paths_by_id[row["execution_path_id"]]["steps"].append(
                    {"step_number": row["step_number"], "action": row["action"]}
                )

        ttp_rows = await _fetch_rows(session, EXECUTION_TTPS_QUERY, {"section_ids": section_ids})
        ttps_by_id: dict[int, dict[str, Any]] = {}
        for row in ttp_rows:
            ttp = {
                "ttp_group": row["ttp_group"],
                "technique_id": row["technique_id"],
                "technique_name": row["technique_name"],
                "procedure": row["procedure"],
                "scope": row["scope"],
                "step_numbers": [],
            }
            ttps_by_id[row["execution_ttp_id"]] = ttp
            if row["execution_path_id"] is None:
                sections_by_id[row["section_id"]]["unplaced_ttps"].append(ttp)
            else:
                paths_by_id[row["execution_path_id"]]["ttps"].append(ttp)

        if ttps_by_id:
            for row in await _fetch_rows(session, TTP_STEPS_QUERY, {"ttp_ids": list(ttps_by_id)}):
                if row["step_number"] is not None:
                    ttps_by_id[row["execution_ttp_id"]]["step_numbers"].append(row["step_number"])
    except HTTPException:
        raise
    except (OSError, SQLAlchemyError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Emerging threat report is temporarily unavailable.",
        ) from error

    return EmergingThreatReportDetail(
        report_id=header["report_id"],
        source_file=header["source_file"],
        client_name=header["client_name"],
        report_type=header["report_type"],
        title=header["title"],
        subtitle=header["subtitle"],
        actor_name=header["actor_name"],
        curation=header["curation"],
        activity_period=EtrActivityPeriod(
            start=header["activity_period_start"],
            end=header["activity_period_end"],
            description=header["activity_period_description"],
        ),
        sections=[
            EmergingThreatReportSection(**sections_by_id[row["section_id"]]) for row in section_rows
        ],
    )
