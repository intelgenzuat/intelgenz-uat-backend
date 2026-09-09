"""Response models for client-specific threat radius distribution."""

from pydantic import BaseModel

from intelgenz_api.modules.intel_cards.schemas import (
    ThreatActorRadiusRange,
    ThreatActorRadiusSeverity,
)


class ThreatActorRadiusDistributionItem(BaseModel):
    actor_id: int
    name: str
    radius: float


class ThreatActorRadiusDistributionResponse(BaseModel):
    client_name: str
    severity: ThreatActorRadiusSeverity
    radius_range: ThreatActorRadiusRange
    total_items: int
    items: list[ThreatActorRadiusDistributionItem]
