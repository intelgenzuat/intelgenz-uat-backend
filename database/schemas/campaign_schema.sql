-- Campaign CTI schema for PostgreSQL / Cloud SQL.
-- This file creates the 23 normalized campaign tables exported by
-- export_campaign_tables.py. It intentionally excludes confidence, sources,
-- and references fields.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS campaign (
    campaign_id BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    node_class TEXT,
    classification TEXT,
    subclassification TEXT,
    reason TEXT,
    description TEXT,
    evidence TEXT,
    ingested_to_kg SMALLINT NOT NULL DEFAULT 0 CHECK (ingested_to_kg IN (0, 1))
);

CREATE TABLE IF NOT EXISTS campaign_alias (
    campaign_alias_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    alias_name TEXT NOT NULL,
    relationship TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_identity (
    campaign_identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    campaign_status TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_tracking_name (
    campaign_tracking_name_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    relationship TEXT,
    vendor TEXT,
    scope_difference TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_boundary (
    campaign_boundary_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    assessment TEXT,
    basis TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_scope (
    campaign_scope_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    first_seen TEXT,
    last_seen TEXT,
    scope_description TEXT,
    targeting_scope TEXT,
    geographic_scope TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_objective (
    campaign_objective_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    objective_id INTEGER,
    type TEXT,
    objective TEXT,
    assessment_basis TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_targeting (
    campaign_targeting_row_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    targeting_id INTEGER,
    target_type TEXT,
    sector TEXT,
    subsector TEXT,
    organization_type TEXT,
    country TEXT,
    region TEXT,
    platform_or_asset TEXT,
    targeting_basis TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_victim (
    campaign_victim_row_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    victim_id INTEGER,
    victim_classification TEXT,
    name TEXT,
    sector TEXT,
    subsector TEXT,
    country TEXT,
    region TEXT,
    affected_asset TEXT,
    incident_date TEXT,
    compromise_status TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_wave (
    campaign_wave_row_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    wave_id TEXT,
    name TEXT,
    start_date TEXT,
    end_date TEXT,
    targeting TEXT,
    delivery_or_access_method TEXT,
    lure_or_theme TEXT,
    malware TEXT,
    tools TEXT,
    notable_changes TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_execution_path (
    campaign_execution_path_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    path_id TEXT,
    wave_id TEXT,
    target_context TEXT,
    evidence_type TEXT
);

CREATE TABLE IF NOT EXISTS campaign_execution_step (
    campaign_execution_step_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    path_id TEXT,
    step INTEGER,
    action TEXT,
    tool TEXT,
    malware TEXT,
    behavior_categories TEXT,
    artifacts TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_unknown_activity (
    campaign_unknown_activity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    activity_number INTEGER,
    activity_id TEXT,
    path_id TEXT,
    wave_id TEXT,
    step INTEGER,
    action TEXT,
    tool TEXT,
    malware TEXT,
    target_context TEXT,
    evidence_type TEXT,
    behavior_categories TEXT,
    artifacts TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_unknown_activity_step (
    campaign_unknown_activity_step_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    activity_number INTEGER,
    step_number INTEGER,
    step INTEGER,
    action TEXT,
    tool TEXT,
    malware TEXT,
    behavior_categories TEXT,
    artifacts TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_mitre_attack (
    campaign_mitre_attack_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    technique_id TEXT,
    technique_name TEXT,
    tactic TEXT,
    wave_id TEXT,
    execution_path_id TEXT,
    execution_step INTEGER,
    malware_or_tool TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_attribution (
    campaign_attribution_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    attribution_status TEXT
);

CREATE TABLE IF NOT EXISTS campaign_attribution_actor (
    campaign_attribution_actor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    actor_name TEXT,
    relationship TEXT,
    attribution_basis TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_related_campaign (
    campaign_related_campaign_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    related_campaign_name TEXT,
    relationship TEXT,
    scope_difference TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_malware_relationship (
    campaign_malware_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    malware_name TEXT,
    relationship TEXT,
    role TEXT,
    wave_id TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_tool_relationship (
    campaign_tool_relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    tool_name TEXT,
    classification TEXT,
    role TEXT,
    wave_id TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_infrastructure (
    campaign_infrastructure_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    infrastructure_id INTEGER,
    value TEXT,
    type TEXT,
    relationship TEXT,
    role TEXT,
    protocol TEXT,
    ports TEXT,
    hosting_or_service TEXT,
    first_seen TEXT,
    last_seen TEXT,
    wave_id TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_vulnerability (
    campaign_vulnerability_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    vulnerability_id INTEGER,
    cve TEXT,
    product TEXT,
    relationship TEXT,
    campaign_role TEXT,
    wave_id TEXT,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS campaign_timeline (
    campaign_timeline_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES public.campaign (campaign_id) ON DELETE CASCADE,
    timeline_id INTEGER,
    date TEXT,
    date_end TEXT,
    event_type TEXT,
    event TEXT,
    wave_id TEXT,
    evidence TEXT
);

CREATE INDEX IF NOT EXISTS idx_campaign_name ON public.campaign (name);
CREATE INDEX IF NOT EXISTS idx_campaign_alias_name ON public.campaign_alias (alias_name);
CREATE INDEX IF NOT EXISTS idx_campaign_targeting_sector ON public.campaign_targeting (sector);
CREATE INDEX IF NOT EXISTS idx_campaign_mitre_technique_id ON public.campaign_mitre_attack (technique_id);
CREATE INDEX IF NOT EXISTS idx_campaign_actor_name ON public.campaign_attribution_actor (actor_name);
CREATE INDEX IF NOT EXISTS idx_campaign_malware_name ON public.campaign_malware_relationship (malware_name);
CREATE INDEX IF NOT EXISTS idx_campaign_infrastructure_value ON public.campaign_infrastructure (value);
CREATE INDEX IF NOT EXISTS idx_campaign_vulnerability_cve ON public.campaign_vulnerability (cve);
CREATE INDEX IF NOT EXISTS idx_campaign_pending_kg ON public.campaign (ingested_to_kg)
    WHERE ingested_to_kg = 0;

-- Verification query: returns the 23 required campaign tables after creation.
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name LIKE 'campaign%'
ORDER BY table_name;
