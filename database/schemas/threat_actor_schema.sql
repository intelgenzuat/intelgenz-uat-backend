-- Threat-actor CTI schema for PostgreSQL / Cloud SQL.
-- Mirrors the 27 worksheets produced by export_threat_actor_tables.py.
-- Confidence, sources, and references are intentionally not stored.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS threat_actor (
    actor_id BIGINT PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    node_class TEXT, entity_classification TEXT, classification_evidence TEXT,
    actor_status TEXT, actor_status_evidence TEXT,
    first_seen TEXT, first_seen_end TEXT, first_seen_precision TEXT, first_seen_raw TEXT, first_seen_evidence TEXT,
    last_seen TEXT, last_seen_end TEXT, last_seen_precision TEXT, last_seen_raw TEXT, last_seen_evidence TEXT,
    sophistication TEXT, sophistication_evidence TEXT,
    resource_level TEXT, resource_level_evidence TEXT,
    ingested_to_kg SMALLINT NOT NULL DEFAULT 0 CHECK (ingested_to_kg IN (0, 1))
);

CREATE TABLE IF NOT EXISTS ta_alias (
    ta_alias_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    alias_name TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_similar_name (
    ta_similar_name_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    similar_name TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_description (
    ta_description_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    description TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_actor_type (
    ta_actor_type_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    actor_type TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_role (
    ta_role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    role TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_motivation (
    ta_motivation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    motivation_category TEXT, type TEXT, description TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_goal (
    ta_goal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    goal TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_nexus (
    ta_nexus_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    country_or_region TEXT, relationship TEXT, basis TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_targeted_asset (
    ta_targeted_asset_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    asset_name TEXT, asset_class TEXT, relationship TEXT, version TEXT, architecture TEXT,
    -- These source fields are not consistently Boolean (for example,
    -- incident_specific_asset can contain "Azure Storage"), so retain them as text.
    environment TEXT, evidence TEXT, incident_specific_asset TEXT, actor_level_targeted_asset TEXT
);
CREATE TABLE IF NOT EXISTS ta_targeting (
    ta_targeting_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    target_type TEXT, sector TEXT, subsector TEXT, organization_type TEXT, country TEXT,
    region TEXT, asset TEXT, campaign TEXT, time_start TEXT, time_end TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_operational_model (
    ta_operational_model_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    actor_type TEXT, role TEXT, model TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_evolution (
    ta_evolution_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    period_start TEXT, period_end TEXT, change_type TEXT, before TEXT, after TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_execution_path (
    ta_execution_path_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    path_id TEXT, campaign TEXT, date_start TEXT, date_end TEXT, target_context TEXT, evidence_origin TEXT
);
CREATE TABLE IF NOT EXISTS ta_execution_step (
    ta_execution_step_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    path_id TEXT, step BIGINT, action TEXT, behavior_categories TEXT, malware TEXT, tools TEXT,
    vulnerabilities TEXT, infrastructure TEXT, artifacts TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_execution_artifact (
    ta_execution_artifact_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    artifact_value TEXT, context TEXT, evidence TEXT, classification TEXT, indicator TEXT, artifact_type TEXT
);
CREATE TABLE IF NOT EXISTS ta_execution_tool (
    ta_execution_tool_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    name TEXT, note TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_mitre_attack (
    ta_mitre_attack_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    technique_id TEXT, technique_name TEXT, tactic TEXT, campaign TEXT, execution_path_id TEXT,
    execution_step BIGINT, malware_or_tool TEXT, procedure TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_actor_relationship (
    ta_actor_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    related_actor_name TEXT, entity_classification TEXT, relationship TEXT, why_not_alias TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_tracking_identity (
    ta_tracking_identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    tracking_identity_name TEXT, relationship TEXT, vendor TEXT, scope_difference TEXT, why_not_alias TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_malware_relationship (
    ta_malware_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    malware_name TEXT, relationship TEXT, role TEXT, campaign TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_tool_relationship (
    ta_tool_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    tool_name TEXT, classification TEXT, relationship TEXT, role TEXT, campaign TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_campaign_relationship (
    ta_campaign_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    campaign_name TEXT, relationship TEXT, role TEXT, time_start TEXT, time_end TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_infrastructure (
    ta_infrastructure_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    infrastructure_value TEXT, infrastructure_type TEXT, relationship TEXT, role TEXT, protocol TEXT, port TEXT,
    hosting_or_service TEXT, first_seen TEXT, last_seen TEXT, campaign TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_vulnerability (
    ta_vulnerability_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    cve TEXT, product TEXT, relationship TEXT, role TEXT, campaign TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_timeline (
    ta_timeline_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    date TEXT, date_end TEXT, precision TEXT, event_type TEXT, event TEXT, campaign TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS ta_indicator (
    ta_indicator_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    indicator_type TEXT, indicator_value TEXT, hash_algorithm TEXT, role TEXT, context TEXT,
    lifecycle_status TEXT, first_seen TEXT, last_seen TEXT, campaign TEXT, evidence TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_actor_canonical_name ON threat_actor(canonical_name);
CREATE INDEX IF NOT EXISTS idx_threat_actor_pending_kg ON threat_actor(ingested_to_kg) WHERE ingested_to_kg = 0;
CREATE INDEX IF NOT EXISTS idx_ta_alias_name ON ta_alias(alias_name);
CREATE INDEX IF NOT EXISTS idx_ta_malware_name ON ta_malware_relationship(malware_name);
CREATE INDEX IF NOT EXISTS idx_ta_campaign_name ON ta_campaign_relationship(campaign_name);
CREATE INDEX IF NOT EXISTS idx_ta_indicator_value ON ta_indicator(indicator_value);
CREATE INDEX IF NOT EXISTS idx_ta_vulnerability_cve ON ta_vulnerability(cve);
CREATE INDEX IF NOT EXISTS idx_ta_mitre_technique ON ta_mitre_attack(technique_id);
