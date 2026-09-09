"""Response models for client-specific threat radius distribution."""

from pydantic import BaseModel

from intelgenz_api.modules.intel_cards.schemas import ThreatActorRadiusSeverity


class ThreatActorRadiusDistributionItem(BaseModel):
    actor_id: int
    name: str
    radius: float
    severity: ThreatActorRadiusSeverity


class ThreatActorRadiusDistributionResponse(BaseModel):
    client_name: str
    total_items: int
    items: list[ThreatActorRadiusDistributionItem]
