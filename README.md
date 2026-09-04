# Intelgenz API

FastAPI service managed with [uv](https://docs.astral.sh/uv/).

## Local development

```powershell
# Install the locked production and development dependencies into .venv
.\.venv\Scripts\uv.exe sync

# Start the API with auto-reload
.\.venv\Scripts\uv.exe run uvicorn intelgenz_api.main:app --reload
```

The interactive API documentation is available at `http://127.0.0.1:8000/docs`.

## Checks

```powershell
.\.venv\Scripts\uv.exe run ruff check .
.\.venv\Scripts\uv.exe run mypy
.\.venv\Scripts\uv.exe run pytest
```

## MITRE ATT&CK matrix data

Download the latest Enterprise ATT&CK matrix into `data/mitre_attack.json`:

```powershell
.\.venv\Scripts\uv.exe run python scripts/fetch_mitre_attack.py
```

The generated file is nested as `tactics -> techniques -> subtechniques` and
includes ATT&CK IDs, descriptions, URLs, platforms, data sources, references,
and lifecycle metadata. Use `--include-retired` to also export deprecated and
revoked content.

## MITRE D3FEND ontology data

Download the current D3FEND ontology JSON-LD graph into `data/d3fend.json`:

```powershell
.\.venv\Scripts\uv.exe run python scripts/fetch_d3fend.py
```

## ATT&CK to D3FEND mappings

Build the complete local cache of D3FEND countermeasures for every ATT&CK
Enterprise technique and sub-technique in `data/mitre_attack.json`:

```powershell
.\.venv\Scripts\uv.exe run python scripts/fetch_attack_d3fend_mappings.py
```

This writes `data/attack_d3fend_mappings.json`. Each ATT&CK ID maps to unique
D3FEND techniques, their defensive tactics, and the inferred artifact paths
used by D3FEND to make the relationship. Re-run the script when refreshing
ATT&CK or D3FEND data; runtime APIs should read this local cache rather than
call D3FEND for every user request.

## Database schemas

Shared PostgreSQL/Cloud SQL DDL lives in `database/schemas/`. Run the required
schema files against the shared database before using the related modules.
Keep future database changes as versioned migrations in `database/migrations/`;
do not modify an already-deployed schema file in place.

Configure the shared database URL in `.env` before using database APIs:

```text
INTELGENZ_DATABASE_URL=postgresql+asyncpg://user:password@host:5432/database
```

Apply `database/migrations/001_malware_search_indexes.sql` after the malware
schema. It enables fast partial matching for the malware type-ahead endpoint:

```text
GET /api/v1/threat-ttps/malware/search?query=em
```

The endpoint returns only the canonical malware ID and name; aliases are used
internally for matching but are not included in the response.

For selected malware, use the batch technique lookup endpoint:

```text
POST /api/v1/threat-ttps/malware/techniques
{
  "malware_ids": [509, 512]
}
```

For the UI, use the combined ATT&CK and D3FEND endpoint instead of making two
separate HTTP requests:

```text
POST /api/v1/threat-ttps/malware/mapping
{
  "malware_ids": [509, 512]
}
```

It returns both top-level `tactics` (ATT&CK) and `d3fend_tactics` (D3FEND).

It returns ATT&CK tactic, technique, and (when relevant) sub-technique names
from `data/mitre_attack.json`, plus the overlap percentage and selected malware
using each technique. A technique used by only one selected malware has `0%`
overlap. Each technique also has its ATT&CK `technique_id`, `overlap_count`,
`has_overlap`, and `malwares` list for direct UI rendering.
Apply
`database/migrations/002_malware_technique_lookup_index.sql` to optimize this
lookup. The search endpoint is optimized by
`database/migrations/001_malware_search_indexes.sql`.

To return recommended D3FEND countermeasures for the same selected malware,
first generate `data/attack_d3fend_mappings.json`, then call:

```text
POST /api/v1/threat-ttps/malware/defenses
{
  "malware_ids": [509, 512]
}
```

The response groups D3FEND techniques under their defensive tactic and shows
the ATT&CK source technique(s) and malware that led to every recommendation.

Download and cache MITRE's D3FEND-to-NIST SP 800-53 Rev. 5 mapping:

```powershell
.\.venv\Scripts\uv.exe run python scripts/fetch_d3fend_nist_mappings.py
```

Then use `POST /api/v1/threat-ttps/malware/nist-controls` with the same
`malware_ids` body. It returns NIST controls grouped by control family and
retains the ATT&CK → D3FEND source chain for each control.

## D3FEND mapping UI

With the API running, open this browser page to search/select malware and view
their D3FEND countermeasures:

```text
http://127.0.0.1:8001/ui/defend_mapping.html
```

## Layout

```text
src/intelgenz_api/
  api/       # versioned API router and health endpoint
  core/      # application configuration
  modules/   # independent product features
    emerging_threats/
    intel_cards/
    threat_ttp_mitigation/
    threat_actor_profiling/
database/
  schemas/   # baseline shared PostgreSQL/Cloud SQL DDL
  migrations/# future versioned database changes
tests/       # automated tests
```
