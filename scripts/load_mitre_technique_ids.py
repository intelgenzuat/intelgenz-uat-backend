"""Create and load searchable MITRE ATT&CK techniques into PostgreSQL."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import asyncpg

from intelgenz_api.core.config import settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = PROJECT_ROOT / "data" / "mitre_attack.json"
MIGRATION_PATH = PROJECT_ROOT / "database" / "migrations" / "007_mitre_technique_ids.sql"


@dataclass
class Technique:
    technique_id: str
    name: str
    description: str | None
    is_subtechnique: bool
    parent_technique_id: str | None
    platforms: list[str]
    mitre_url: str | None
    source_created_at: datetime | None
    modified_at: datetime | None
    tactics: dict[str, dict[str, str]] = field(default_factory=dict)


def get_database_url() -> str:
    """Return the configured asyncpg connection URL."""
    database_url = settings.resolved_database_url
    if database_url is None:
        raise RuntimeError("Database settings are not configured.")
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


def parse_datetime(value: object) -> datetime | None:
    """Convert a STIX timestamp to a timezone-aware Python datetime."""
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iter_techniques(
    document: dict[str, object],
) -> Iterator[tuple[dict[str, object], dict[str, str]]]:
    """Yield each parent technique and nested sub-technique with its tactic."""
    tactics = document.get("tactics", [])
    if not isinstance(tactics, list):
        raise ValueError("MITRE data does not contain a tactics list.")

    for tactic in tactics:
        if not isinstance(tactic, dict):
            continue
        tactic_id = tactic.get("tactic_id")
        tactic_name = tactic.get("name")
        if not isinstance(tactic_id, str) or not isinstance(tactic_name, str):
            continue
        tactic_value = {"tactic_id": tactic_id, "name": tactic_name}
        techniques = tactic.get("techniques", [])
        if not isinstance(techniques, list):
            continue
        for technique in techniques:
            if not isinstance(technique, dict):
                continue
            yield technique, tactic_value
            subtechniques = technique.get("subtechniques", [])
            if isinstance(subtechniques, list):
                for subtechnique in subtechniques:
                    if isinstance(subtechnique, dict):
                        yield subtechnique, tactic_value


def read_techniques() -> list[Technique]:
    """Flatten the ATT&CK JSON into unique technique and sub-technique records."""
    with SOURCE_PATH.open(encoding="utf-8") as source_file:
        document = json.load(source_file)
    if not isinstance(document, dict):
        raise ValueError("MITRE data must be a JSON object.")

    techniques_by_id: dict[str, Technique] = {}
    for source_technique, tactic in iter_techniques(document):
        technique_id = source_technique.get("technique_id")
        name = source_technique.get("name")
        if not isinstance(technique_id, str) or not isinstance(name, str):
            continue

        technique = techniques_by_id.get(technique_id)
        if technique is None:
            is_subtechnique = bool(source_technique.get("is_subtechnique"))
            parent_id = technique_id.rsplit(".", 1)[0] if is_subtechnique else None
            platforms = source_technique.get("platforms", [])
            technique = Technique(
                technique_id=technique_id,
                name=name,
                description=source_technique.get("description")
                if isinstance(source_technique.get("description"), str)
                else None,
                is_subtechnique=is_subtechnique,
                parent_technique_id=parent_id,
                platforms=sorted({item for item in platforms if isinstance(item, str)})
                if isinstance(platforms, list)
                else [],
                mitre_url=source_technique.get("url")
                if isinstance(source_technique.get("url"), str)
                else None,
                source_created_at=parse_datetime(source_technique.get("created")),
                modified_at=parse_datetime(source_technique.get("modified")),
            )
            techniques_by_id[technique_id] = technique
        technique.tactics[tactic["tactic_id"]] = tactic

    return sorted(techniques_by_id.values(), key=lambda technique: technique.technique_id)


async def load_mitre_technique_ids() -> int:
    """Apply the migration and upsert the local ATT&CK source data."""
    techniques = read_techniques()
    connection = await asyncpg.connect(get_database_url())
    try:
        await connection.execute(MIGRATION_PATH.read_text(encoding="utf-8"))
        await connection.executemany(
            """
            INSERT INTO public.mitre_technique_ids (
                technique_id, name, description, is_subtechnique, parent_technique_id,
                tactic_names, tactics, platforms, mitre_url, source_created_at, modified_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
            ON CONFLICT (technique_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                is_subtechnique = EXCLUDED.is_subtechnique,
                parent_technique_id = EXCLUDED.parent_technique_id,
                tactic_names = EXCLUDED.tactic_names,
                tactics = EXCLUDED.tactics,
                platforms = EXCLUDED.platforms,
                mitre_url = EXCLUDED.mitre_url,
                source_created_at = EXCLUDED.source_created_at,
                modified_at = EXCLUDED.modified_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            [
                (
                    technique.technique_id,
                    technique.name,
                    technique.description,
                    technique.is_subtechnique,
                    technique.parent_technique_id,
                    sorted(tactic["name"] for tactic in technique.tactics.values()),
                    json.dumps(list(technique.tactics.values())),
                    technique.platforms,
                    technique.mitre_url,
                    technique.source_created_at,
                    technique.modified_at,
                )
                for technique in techniques
            ],
        )
        return len(techniques)
    finally:
        await connection.close()


if __name__ == "__main__":
    loaded_rows = asyncio.run(load_mitre_technique_ids())
    print(f"Loaded {loaded_rows} MITRE ATT&CK techniques and sub-techniques.")
