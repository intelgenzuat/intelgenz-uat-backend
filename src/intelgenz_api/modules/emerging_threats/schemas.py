"""UI-focused response models for client-specific emerging threat reports."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field


class EtrActivityPeriod(BaseModel):
    start: str | None = None
    end: str | None = None


class EtrListReport(BaseModel):
    title: str | None = None
    activity_period: EtrActivityPeriod


class EtrListImpactOverview(BaseModel):
    type: Literal["impact_overview"] = "impact_overview"
    affected_regions: list[str] = Field(default_factory=list)
    affected_countries: list[str] = Field(default_factory=list)
    affected_sectors: list[str] = Field(default_factory=list)
    severity: str | None = None


class EmergingThreatReportListItem(BaseModel):
    """Card data; report_id is retained only for the View Report request."""

    report_id: int
    report: EtrListReport
    sections: list[EtrListImpactOverview]


class EmergingThreatReportListPage(BaseModel):
    client_name: str | None = None
    page: int
    page_size: int = 6
    total_items: int
    total_pages: int
    items: list[EmergingThreatReportListItem]


class EtrItemMapping(BaseModel):
    framework: str | None = None
    mapping_id: str | None = None
    mapping_name: str | None = None
    rationale: str | None = None


class EtrSectionItem(BaseModel):
    item_kind: str
    item_id: str | None = None
    item_name: str | None = None
    title: str | None = None
    procedure: str | None = None
    scope: str | None = None
    addresses: list[str] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)
    mappings: list[EtrItemMapping] = Field(default_factory=list)


class EtrExecutionStep(BaseModel):
    step_number: int | None = None
    action: str | None = None


class EtrExecutionTtp(BaseModel):
    ttp_group: str
    technique_id: str | None = None
    technique_name: str | None = None
    procedure: str | None = None
    scope: str | None = None
    step_numbers: list[int] = Field(default_factory=list)


class EtrExecutionPath(BaseModel):
    title: str | None = None
    description: list[str] = Field(default_factory=list)
    activity_period: EtrActivityPeriod
    steps: list[EtrExecutionStep] = Field(default_factory=list)
    ttps: list[EtrExecutionTtp] = Field(default_factory=list)


class EtrImpactOverviewSection(BaseModel):
    type: Literal["impact_overview"] = "impact_overview"
    affected_platforms: list[str] = Field(default_factory=list)
    impacted_users: list[str] = Field(default_factory=list)
    impact: str | None = None
    severity: str | None = None
    affected_regions: list[str] = Field(default_factory=list)
    affected_countries: list[str] = Field(default_factory=list)
    affected_sectors: list[str] = Field(default_factory=list)


class EtrNarrativeSection(BaseModel):
    title: str | None = None
    content: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    type: Literal["narrative"] = "narrative"
    role: Literal["actor_introduction", "story_introduction", "body", "conclusion"]


class EtrExecutionSection(BaseModel):
    title: str | None = None
    summary: list[str] = Field(default_factory=list)
    paths: list[EtrExecutionPath] = Field(default_factory=list)
    type: Literal["execution"] = "execution"


class EtrDefenseGuidanceSection(BaseModel):
    type: Literal["defense_guidance"] = "defense_guidance"
    title: str | None = None
    items: list[EtrSectionItem] = Field(default_factory=list)


EtrViewSection = Annotated[
    EtrImpactOverviewSection
    | EtrNarrativeSection
    | EtrExecutionSection
    | EtrDefenseGuidanceSection,
    Field(discriminator="type"),
]


class EtrViewReport(BaseModel):
    title: str | None = None
    subtitle: str | None = None
    author: str | None = None
    activity_period: EtrActivityPeriod


class EtrViewActor(BaseModel):
    name: str | None = None


class EmergingThreatReportDetail(BaseModel):
    report: EtrViewReport
    actor: EtrViewActor
    sections: list[EtrViewSection]
