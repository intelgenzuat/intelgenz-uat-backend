"""Read the local MITRE ATT&CK matrix export for human-readable mappings."""

import json
from dataclasses import dataclass
from functools import lru_cache

from intelgenz_api.core.config import settings


@dataclass(frozen=True)
class MitreTechniqueContext:
    technique_id: str
    tactic_name: str
    tactic_order: int
    technique_name: str
    subtechnique_name: str | None


@lru_cache
def get_mitre_technique_index() -> dict[str, tuple[MitreTechniqueContext, ...]]:
    """Index technique IDs by their tactic and display names from the local export."""
    payload = json.loads(settings.mitre_attack_data_path.read_text(encoding="utf-8"))
    tactics = payload.get("tactics", [])
    if not isinstance(tactics, list):
        raise ValueError("MITRE ATT&CK data does not contain a tactics list.")

    contexts_by_technique_id: dict[str, set[MitreTechniqueContext]] = {}
    for tactic_order, tactic in enumerate(tactics):
        if not isinstance(tactic, dict) or not isinstance(tactic.get("name"), str):
            continue
        techniques = tactic.get("techniques", [])
        if not isinstance(techniques, list):
            continue

        for technique in techniques:
            if not isinstance(technique, dict) or not isinstance(technique.get("name"), str):
                continue
            technique_id = technique.get("technique_id")
            if isinstance(technique_id, str):
                context = MitreTechniqueContext(
                    technique_id=technique_id,
                    tactic_name=tactic["name"],
                    tactic_order=tactic_order,
                    technique_name=technique["name"],
                    subtechnique_name=None,
                )
                contexts_by_technique_id.setdefault(technique_id, set()).add(context)

            subtechniques = technique.get("subtechniques", [])
            if not isinstance(subtechniques, list):
                continue
            for subtechnique in subtechniques:
                if not isinstance(subtechnique, dict) or not isinstance(
                    subtechnique.get("technique_id"), str
                ):
                    continue
                subtechnique_name = subtechnique.get("name")
                if not isinstance(subtechnique_name, str):
                    continue
                context = MitreTechniqueContext(
                    technique_id=subtechnique["technique_id"],
                    tactic_name=tactic["name"],
                    tactic_order=tactic_order,
                    technique_name=technique["name"],
                    subtechnique_name=subtechnique_name,
                )
                contexts_by_technique_id.setdefault(subtechnique["technique_id"], set()).add(
                    context
                )

    return {
        technique_id: tuple(
            sorted(
                contexts,
                key=lambda context: (
                    context.tactic_order,
                    context.technique_name,
                    context.subtechnique_name or "",
                ),
            )
        )
        for technique_id, contexts in contexts_by_technique_id.items()
    }
