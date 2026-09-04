"""Read the local D3FEND-to-NIST SP 800-53 Rev. 5 mapping cache."""

import json
from dataclasses import dataclass
from functools import lru_cache

from intelgenz_api.core.config import settings


@dataclass(frozen=True)
class NistControlMapping:
    catalog: str
    control_id: str
    relation: str


def binding_value(binding: dict[str, object], name: str) -> str | None:
    value = binding.get(name)
    if not isinstance(value, dict):
        return None
    text = value.get("value")
    return text if isinstance(text, str) else None


@lru_cache
def get_d3fend_nist_index() -> dict[str, tuple[NistControlMapping, ...]]:
    """Index NIST controls by the D3FEND technique label used in the cache."""
    payload = json.loads(settings.d3fend_nist_mappings_path.read_text(encoding="utf-8"))
    results = payload.get("results", {})
    bindings = results.get("bindings", []) if isinstance(results, dict) else []
    if not isinstance(bindings, list):
        raise ValueError("D3FEND NIST data does not contain result bindings.")

    mappings: dict[str, set[NistControlMapping]] = {}
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        technique_name = binding_value(binding, "Technique")
        catalog = binding_value(binding, "Catalog")
        control_id = binding_value(binding, "Control")
        relation = binding_value(binding, "Relation")
        if (
            technique_name is None
            or catalog is None
            or control_id is None
            or relation is None
        ):
            continue
        mappings.setdefault(technique_name, set()).add(
            NistControlMapping(catalog, control_id, relation)
        )
    return {
        name: tuple(sorted(items, key=lambda item: item.control_id))
        for name, items in mappings.items()
    }
