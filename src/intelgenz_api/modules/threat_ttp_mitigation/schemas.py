from pydantic import BaseModel, Field, field_validator


class MalwareSearchItem(BaseModel):
    malware_id: int
    name: str


class MalwareSearchResponse(BaseModel):
    query: str
    results: list[MalwareSearchItem]


class MalwareTechniqueRequest(BaseModel):
    malware_ids: list[int] = Field(min_length=1, max_length=100)

    @field_validator("malware_ids")
    @classmethod
    def malware_ids_must_be_unique(cls, malware_ids: list[int]) -> list[int]:
        if len(malware_ids) != len(set(malware_ids)):
            raise ValueError("malware_ids must not contain duplicates.")
        return malware_ids


class MalwareUsingTechnique(BaseModel):
    malware_id: int
    name: str


class TechniqueMappingItem(BaseModel):
    technique_id: str
    technique_name: str
    subtechnique_name: str | None
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    malwares: list[MalwareUsingTechnique]


class TacticTechniqueMapping(BaseModel):
    tactic_name: str
    techniques: list[TechniqueMappingItem]


class MalwareTechniqueResponse(BaseModel):
    selected_malware_count: int
    tactics: list[TacticTechniqueMapping]


class AttackTechniqueDefenseSource(BaseModel):
    technique_id: str
    technique_name: str
    subtechnique_name: str | None
    tactics: list[str]
    malwares: list[MalwareUsingTechnique]


class D3fendTechniqueMappingItem(BaseModel):
    d3fend_id: str
    name: str
    parent_technique: str | None
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    malwares: list[MalwareUsingTechnique]
    attack_techniques: list[AttackTechniqueDefenseSource]


class D3fendTacticMapping(BaseModel):
    tactic_name: str
    techniques: list[D3fendTechniqueMappingItem]


class MalwareDefenseResponse(BaseModel):
    selected_malware_count: int
    d3fend_tactics: list[D3fendTacticMapping]


class NistD3fendSource(BaseModel):
    d3fend_id: str
    name: str
    attack_technique_ids: list[str]


class NistControlMappingItem(BaseModel):
    catalog: str
    control_id: str
    relations: list[str]
    overlap_count: int
    overlap_percentage: int
    has_overlap: bool
    malwares: list[MalwareUsingTechnique]
    d3fend_techniques: list[NistD3fendSource]


class NistControlFamilyMapping(BaseModel):
    family_id: str
    family_name: str
    controls: list[NistControlMappingItem]


class MalwareTtpDefenseMappingResponse(BaseModel):
    selected_malware_count: int
    tactics: list[TacticTechniqueMapping]
    d3fend_tactics: list[D3fendTacticMapping]
    nist_control_families: list[NistControlFamilyMapping]


class MalwareNistResponse(BaseModel):
    selected_malware_count: int
    nist_control_families: list[NistControlFamilyMapping]
