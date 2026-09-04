"""Read the local ATT&CK-to-D3FEND mapping cache."""

import json
from dataclasses import dataclass
from functools import lru_cache

from intelgenz_api.core.config import settings


@dataclass(frozen=True)
class D3fendTechniqueContext:
    d3fend_id: str
    name: str
    parent_technique: str | None
    tactics: tuple[str, ...]


@lru_cache
def get_attack_d3fend_index() -> dict[str, tuple[D3fendTechniqueContext, ...]]:
    """Index local D3FEND techniques by source ATT&CK technique ID."""
    payload = json.loads(settings.attack_d3fend_mappings_path.read_text(encoding="utf-8"))
    mappings = payload.get("mappings", {})
    if not isinstance(mappings, dict):
        raise ValueError("ATT&CK-to-D3FEND data does not contain a mappings object.")

    index: dict[str, tuple[D3fendTechniqueContext, ...]] = {}
    for attack_technique_id, mapping in mappings.items():
        if not isinstance(attack_technique_id, str) or not isinstance(mapping, dict):
            continue
        d3fend_techniques = mapping.get("d3fend_techniques", [])
        if not isinstance(d3fend_techniques, list):
            continue

        contexts: list[D3fendTechniqueContext] = []
        for technique in d3fend_techniques:
            if not isinstance(technique, dict):
                continue
            d3fend_id = technique.get("d3fend_id")
            name = technique.get("name")
            tactics = technique.get("tactics")
            if (
                not isinstance(d3fend_id, str)
                or not isinstance(name, str)
                or not isinstance(tactics, list)
                or not all(isinstance(tactic, str) for tactic in tactics)
            ):
                continue
            parent_technique = technique.get("parent_technique")
            contexts.append(
                D3fendTechniqueContext(
                    d3fend_id=d3fend_id,
                    name=name,
                    parent_technique=(
                        parent_technique if isinstance(parent_technique, str) else None
                    ),
                    tactics=tuple(sorted(tactics)),
                )
            )
        index[attack_technique_id] = tuple(sorted(contexts, key=lambda item: item.d3fend_id))
    return index
