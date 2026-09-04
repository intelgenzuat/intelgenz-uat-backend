"""Fetch the MITRE ATT&CK Enterprise matrix into a nested JSON document.

The output is grouped as tactic -> technique -> sub-technique and is sourced
from MITRE's official Enterprise ATT&CK STIX bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
MATRIX_TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/mitre_attack.json"),
        help="Destination JSON file (default: data/mitre_attack.json).",
    )
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help="Enterprise ATT&CK STIX bundle URL.",
    )
    parser.add_argument(
        "--include-retired",
        action="store_true",
        help="Include revoked and deprecated tactics and techniques.",
    )
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout in seconds.")
    return parser.parse_args()


def download_bundle(source_url: str, timeout: int) -> tuple[dict[str, object], str]:
    """Download and validate a MITRE ATT&CK STIX bundle."""
    request = Request(source_url, headers={"User-Agent": "intelgenz-api/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is CLI input.
            body = response.read()
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Could not download MITRE ATT&CK data: {error}") from error

    try:
        bundle = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError("MITRE ATT&CK source did not return valid JSON.") from error

    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise RuntimeError("MITRE ATT&CK source is not a STIX bundle with an objects list.")

    return bundle, hashlib.sha256(body).hexdigest()


def is_visible(stix_object: dict[str, object], include_retired: bool) -> bool:
    """Return whether an object is displayed in the current ATT&CK matrix."""
    return include_retired or not bool(
        stix_object.get("revoked") or stix_object.get("x_mitre_deprecated")
    )


def external_id(stix_object: dict[str, object]) -> str | None:
    """Extract MITRE's human-readable TAxxxx or Txxxx identifier."""
    references = stix_object.get("external_references", [])
    if not isinstance(references, list):
        return None

    for reference in references:
        if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
            identifier = reference.get("external_id")
            return identifier if isinstance(identifier, str) else None
    return None


def attack_url(stix_object: dict[str, object]) -> str | None:
    """Extract the ATT&CK website URL for an object, if provided."""
    references = stix_object.get("external_references", [])
    if not isinstance(references, list):
        return None

    for reference in references:
        if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
            url = reference.get("url")
            return url if isinstance(url, str) else None
    return None


def tactic_phases(technique: dict[str, object]) -> set[str]:
    """Return Enterprise ATT&CK tactic short names associated with a technique."""
    phases = technique.get("kill_chain_phases", [])
    if not isinstance(phases, list):
        return set()

    return {
        phase_name
        for phase in phases
        if isinstance(phase, dict)
        and phase.get("kill_chain_name") == "mitre-attack"
        and isinstance(phase_name := phase.get("phase_name"), str)
    }


def technique_payload(
    technique: dict[str, object], subtechniques: list[dict[str, object]] | None = None
) -> dict[str, object]:
    """Return the useful ATT&CK fields for a technique or sub-technique."""
    payload: dict[str, object] = {
        "technique_id": external_id(technique),
        "stix_id": technique["id"],
        "name": technique["name"],
        "description": technique.get("description", ""),
        "url": attack_url(technique),
        "is_subtechnique": bool(technique.get("x_mitre_is_subtechnique")),
        "platforms": technique.get("x_mitre_platforms", []),
        "data_sources": technique.get("x_mitre_data_sources", []),
        "detection": technique.get("x_mitre_detection", ""),
        "permissions_required": technique.get("x_mitre_permissions_required", []),
        "effective_permissions": technique.get("x_mitre_effective_permissions", []),
        "defense_bypassed": technique.get("x_mitre_defense_bypassed", []),
        "system_requirements": technique.get("x_mitre_system_requirements", []),
        "contributors": technique.get("x_mitre_contributors", []),
        "version": technique.get("x_mitre_version"),
        "created": technique.get("created"),
        "modified": technique.get("modified"),
        "deprecated": bool(technique.get("x_mitre_deprecated")),
        "revoked": bool(technique.get("revoked")),
        "references": technique.get("external_references", []),
    }
    if subtechniques is not None:
        payload["subtechniques"] = subtechniques
    return payload


def build_matrix(bundle: dict[str, object], include_retired: bool) -> dict[str, object]:
    """Transform a STIX bundle into the application-friendly ATT&CK matrix."""
    raw_objects = bundle["objects"]
    assert isinstance(raw_objects, list)
    objects = [item for item in raw_objects if isinstance(item, dict)]

    tactics = [
        item
        for item in objects
        if item.get("type") == "x-mitre-tactic" and is_visible(item, include_retired)
    ]
    techniques = {
        item["id"]: item
        for item in objects
        if item.get("type") == "attack-pattern"
        and isinstance(item.get("id"), str)
        and is_visible(item, include_retired)
    }
    parent_by_subtechnique = {
        relationship["source_ref"]: relationship["target_ref"]
        for relationship in objects
        if relationship.get("type") == "relationship"
        and relationship.get("relationship_type") == "subtechnique-of"
        and isinstance(relationship.get("source_ref"), str)
        and isinstance(relationship.get("target_ref"), str)
        and is_visible(relationship, include_retired)
    }

    subtechniques_by_parent: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for technique_id, technique in techniques.items():
        if not technique.get("x_mitre_is_subtechnique"):
            continue
        parent_id = parent_by_subtechnique.get(technique_id)
        if parent_id in techniques:
            subtechniques_by_parent[parent_id].append(technique)

    tactic_by_shortname = {
        tactic.get("x_mitre_shortname"): tactic
        for tactic in tactics
        if isinstance(tactic.get("x_mitre_shortname"), str)
    }
    ordered_shortnames = [
        shortname for shortname in MATRIX_TACTIC_ORDER if shortname in tactic_by_shortname
    ]
    ordered_shortnames.extend(
        sorted(set(tactic_by_shortname) - set(ordered_shortnames))
    )

    matrix_tactics: list[dict[str, object]] = []
    for shortname in ordered_shortnames:
        tactic = tactic_by_shortname[shortname]
        parent_ids = {
            technique_id
            for technique_id, technique in techniques.items()
            if not technique.get("x_mitre_is_subtechnique")
            and shortname in tactic_phases(technique)
        }
        parent_ids.update(
            parent_by_subtechnique[technique_id]
            for technique_id, technique in techniques.items()
            if technique.get("x_mitre_is_subtechnique")
            and shortname in tactic_phases(technique)
            and parent_by_subtechnique.get(technique_id) in techniques
        )

        matrix_techniques = []
        for parent_id in sorted(parent_ids, key=lambda value: str(external_id(techniques[value]))):
            subtechniques = [
                technique_payload(subtechnique)
                for subtechnique in sorted(
                    (
                        item
                        for item in subtechniques_by_parent[parent_id]
                        if shortname in tactic_phases(item)
                    ),
                    key=lambda value: str(external_id(value)),
                )
            ]
            matrix_techniques.append(technique_payload(techniques[parent_id], subtechniques))

        matrix_tactics.append(
            {
                "tactic_id": external_id(tactic),
                "stix_id": tactic["id"],
                "name": tactic["name"],
                "shortname": shortname,
                "description": tactic.get("description", ""),
                "url": attack_url(tactic),
                "version": tactic.get("x_mitre_version"),
                "created": tactic.get("created"),
                "modified": tactic.get("modified"),
                "techniques": matrix_techniques,
            }
        )

    return {"tactics": matrix_tactics}


def write_json(output_path: Path, payload: dict[str, object]) -> None:
    """Write JSON atomically so a failed refresh never corrupts the old file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
    serialized_payload = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    temporary_path.write_text(serialized_payload, encoding="utf-8")
    temporary_path.replace(output_path)


def main() -> None:
    arguments = parse_arguments()
    bundle, checksum = download_bundle(arguments.source_url, arguments.timeout)
    payload = {
        "schema_version": "1.0",
        "source": {
            "name": "MITRE ATT&CK Enterprise STIX",
            "url": arguments.source_url,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "sha256": checksum,
            "include_retired": arguments.include_retired,
        },
        **build_matrix(bundle, arguments.include_retired),
    }
    write_json(arguments.output, payload)
    print(f"Wrote {len(payload['tactics'])} tactics to {arguments.output}")


if __name__ == "__main__":
    main()
