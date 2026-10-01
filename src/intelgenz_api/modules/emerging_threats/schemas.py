"""Response models for client-specific emerging threat reports."""

from pydantic import BaseModel, Field


class EtrActivityPeriod(BaseModel):
    start: str | None = None
    end: str | None = None
    description: str | None = None


class EtrTargeting(BaseModel):
    regions: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)


class EmergingThreatReportListItem(BaseModel):
    report_id: int
    title: str | None = None
    subtitle: str | None = None
    actor_name: str | None = None
    report_type: str | None = None
    curation: str | None = None
    activity_period: EtrActivityPeriod
    targeting: EtrTargeting
    severity: str | None = None


class EmergingThreatReportListPage(BaseModel):
    client_name: str
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
    campaign: str | None = None
    coverage_note: str | None = None
    description: list[str] = Field(default_factory=list)
    mermaid: str | None = None
    activity_period: EtrActivityPeriod
    steps: list[EtrExecutionStep] = Field(default_factory=list)
    ttps: list[EtrExecutionTtp] = Field(default_factory=list)


class EmergingThreatReportSection(BaseModel):
    section_type: str
    title: str | None = None
    content: list[str] = Field(default_factory=list)
    summary: list[str] = Field(default_factory=list)
    impact: str | None = None
    severity: str | None = None
    affected_platforms: list[str] = Field(default_factory=list)
    impacted_users: list[str] = Field(default_factory=list)
    targeting: EtrTargeting
    items: list[EtrSectionItem] = Field(default_factory=list)
    execution_paths: list[EtrExecutionPath] = Field(default_factory=list)
    unplaced_ttps: list[EtrExecutionTtp] = Field(default_factory=list)


class EmergingThreatReportDetail(BaseModel):
    report_id: int
    source_file: str
    client_name: str
    report_type: str | None = None
    title: str | None = None
    subtitle: str | None = None
    actor_name: str | None = None
    curation: str | None = None
    activity_period: EtrActivityPeriod
    sections: list[EmergingThreatReportSection]
