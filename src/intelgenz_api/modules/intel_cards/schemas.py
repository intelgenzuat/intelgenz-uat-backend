from pydantic import BaseModel


class MalwareCardNameRelationship(BaseModel):
    name: str
    relationship: str | None


class MalwareCardPlatform(BaseModel):
    platform: str | None
    version: str | None


class MalwareCardComponent(BaseModel):
    name: str | None
    type: str | None
    role: str | None


class MalwareCardComponentRelationship(BaseModel):
    source_component_id: str
    target_component_id: str
    relationship: str


class MalwareCardSummary(BaseModel):
    classification: str | None
    malware_type: str | None
    family: str | None
    family_relationship: str | None
    primary_capability: str | None
    secondary_capabilities: list[str]
    associated_threat_actors: list[MalwareCardNameRelationship]
    associated_malware: list[MalwareCardNameRelationship]
    affected_platforms: list[MalwareCardPlatform]
    components: list[MalwareCardComponent]
    component_relationships: list[MalwareCardComponentRelationship]
    variants: list[str]
    predecessors: list[str]
    successors: list[str]
    evolution_summary: str | None


class MalwareCardTimelineItem(BaseModel):
    date: str | None
    date_end: str | None
    activity: str


class MalwareCardExecutionStep(BaseModel):
    step: int
    title: str
    action: str | None
    categories: list[str]
    component: str | None
    tools: list[str]
    artifacts: list[str]


class MalwareCardExecutionPath(BaseModel):
    path_id: str
    steps: list[MalwareCardExecutionStep]


class MalwareCardExecution(BaseModel):
    confirmed_paths: list[MalwareCardExecutionPath]


class MalwareCardTool(BaseModel):
    name: str
    type: str | None
    purpose: str | None


class MalwareCardInfrastructure(BaseModel):
    value: str
    type: str | None
    role: str | None
    protocol: str | None
    ports: list[str]
    service: str | None


class MalwareCardArtifact(BaseModel):
    value: str
    type: str
    purpose: str | None


class MalwareCardIoc(BaseModel):
    type: str | None
    value: str
    role: str | None
    context: str | None
    first_seen: str | None
    last_seen: str | None


class MalwareCardTtp(BaseModel):
    tactic: str | None
    technique_id: str
    technique: str | None
    usage: str | None


class MalwareIntelCard(BaseModel):
    malware_id: int
    name: str
    aliases: list[str]
    summary: MalwareCardSummary
    description: str | None
    activity_timeline: list[MalwareCardTimelineItem]
    execution: MalwareCardExecution
    tools_used: list[MalwareCardTool]
    infrastructure: list[MalwareCardInfrastructure]
    artifacts: list[MalwareCardArtifact]
    iocs: list[MalwareCardIoc]
    ttps: list[MalwareCardTtp]


class MalwareCardPagination(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int


class MalwareIntelCardPage(BaseModel):
    pagination: MalwareCardPagination
    items: list[MalwareIntelCard]


class ThreatActorCardNexus(BaseModel):
    country_or_region: str | None
    relationship: str | None


class ThreatActorCardTargeting(BaseModel):
    sectors: list[str]
    countries: list[str]
    regions: list[str]


class ThreatActorCardTargetedAsset(BaseModel):
    name: str | None
    environment: str | None


class ThreatActorCardMotivation(BaseModel):
    type: str | None


class ThreatActorCardDate(BaseModel):
    date: str | None


class ThreatActorCardLastSeen(BaseModel):
    date: str | None
    raw_value: str | None


class ThreatActorCardSummary(BaseModel):
    classification: str | None
    status: str | None
    actor_types: list[str]
    roles: list[str]
    sophistication: str | None
    resource_level: str | None
    primary_motivation: ThreatActorCardMotivation
    goals: list[str]
    first_seen: ThreatActorCardDate
    last_seen: ThreatActorCardLastSeen
    nexus: list[ThreatActorCardNexus]
    targeting: list[ThreatActorCardTargeting]
    targeted_assets: list[ThreatActorCardTargetedAsset]


class ThreatActorCardTimelineItem(BaseModel):
    date: str | None
    date_end: str | None
    precision: str | None
    event_type: str | None
    event: str
    campaign: str | None


class ThreatActorCardExecutionStep(BaseModel):
    step: int | None
    title: str
    action: str | None
    categories: list[str]
    malware: list[str]
    tools: list[str]
    vulnerabilities: list[str]
    infrastructure: list[str]
    artifacts: list[str]


class ThreatActorCardExecutionPath(BaseModel):
    campaign: str | None
    date_start: str | None
    date_end: str | None
    target_context: str | None
    steps: list[ThreatActorCardExecutionStep]


class ThreatActorCardObservedActivity(BaseModel):
    activity: str
    categories: list[str]
    campaign: str | None
    malware: list[str]
    tools: list[str]
    vulnerabilities: list[str]
    infrastructure: list[str]
    artifacts: list[str]


class ThreatActorCardExecution(BaseModel):
    confirmed_paths: list[ThreatActorCardExecutionPath]
    observed_activities: list[ThreatActorCardObservedActivity]


class ThreatActorCardCapability(BaseModel):
    name: str
    type: str | None
    relationship: str | None
    role: str | None


class ThreatActorCardInfrastructure(BaseModel):
    value: str
    type: str | None
    role: str | None
    protocol: str | None
    port: str | None
    service: str | None


class ThreatActorCardVulnerability(BaseModel):
    cve: str | None
    product: str | None
    relationship: str | None
    role: str | None


class ThreatActorCardTtp(BaseModel):
    tactic: str | None
    technique_id: str | None
    technique: str | None
    procedure: str | None


class ThreatActorCardIoc(BaseModel):
    type: str | None
    value: str
    hash_algorithm: str | None
    role: str | None
    context: str | None
    first_seen: str | None
    last_seen: str | None


class ThreatActorIntelCard(BaseModel):
    actor_id: int
    name: str
    aliases: list[str]
    summary: ThreatActorCardSummary
    description: str | None
    activity_timeline: list[ThreatActorCardTimelineItem]
    execution: ThreatActorCardExecution
    capabilities: list[ThreatActorCardCapability]
    infrastructure: list[ThreatActorCardInfrastructure]
    vulnerabilities: list[ThreatActorCardVulnerability]
    ttps: list[ThreatActorCardTtp]
    iocs: list[ThreatActorCardIoc]


class ThreatActorIntelCardPage(BaseModel):
    pagination: MalwareCardPagination
    items: list[ThreatActorIntelCard]
