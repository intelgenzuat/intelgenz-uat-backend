from pydantic import BaseModel, Field, field_validator


class ThreatActorSearchItem(BaseModel):
    actor_id: int
    name: str


class ThreatActorSearchResponse(BaseModel):
    query: str
    results: list[ThreatActorSearchItem]


class ThreatActorMappingRequest(BaseModel):
    actor_ids: list[int] = Field(min_length=1, max_length=100)

    @field_validator("actor_ids")
    @classmethod
    def actor_ids_must_be_unique(cls, actor_ids: list[int]) -> list[int]:
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("actor_ids must not contain duplicates.")
        return actor_ids


class ThreatActorUsingTechnique(BaseModel):
    actor_id: int
    name: str


class ThreatActorTechniqueMappingItem(BaseModel):
    technique_id: str
    technique_name: str
    subtechnique_name: str | None
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    actors: list[ThreatActorUsingTechnique]


class ThreatActorTacticTechniqueMapping(BaseModel):
    tactic_name: str
    techniques: list[ThreatActorTechniqueMappingItem]


class ThreatActorAttackTechniqueDefenseSource(BaseModel):
    technique_id: str
    technique_name: str
    subtechnique_name: str | None
    tactics: list[str]
    actors: list[ThreatActorUsingTechnique]


class ThreatActorD3fendTechniqueMappingItem(BaseModel):
    d3fend_id: str
    name: str
    parent_technique: str | None
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    actors: list[ThreatActorUsingTechnique]
    attack_techniques: list[ThreatActorAttackTechniqueDefenseSource]


class ThreatActorD3fendTacticMapping(BaseModel):
    tactic_name: str
    techniques: list[ThreatActorD3fendTechniqueMappingItem]


class ThreatActorNistD3fendSource(BaseModel):
    d3fend_id: str
    name: str
    attack_technique_ids: list[str]


class ThreatActorNistControlMappingItem(BaseModel):
    catalog: str
    control_id: str
    relations: list[str]
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    actors: list[ThreatActorUsingTechnique]
    d3fend_techniques: list[ThreatActorNistD3fendSource]


class ThreatActorNistControlFamilyMapping(BaseModel):
    family_id: str
    family_name: str
    controls: list[ThreatActorNistControlMappingItem]


class ThreatActorMappingResponse(BaseModel):
    selected_actor_count: int
    tactics: list[ThreatActorTacticTechniqueMapping]
    d3fend_tactics: list[ThreatActorD3fendTacticMapping]
    nist_control_families: list[ThreatActorNistControlFamilyMapping]
