CREATE TABLE IF NOT EXISTS public.mitre_technique_ids (
    technique_id VARCHAR(20) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    is_subtechnique BOOLEAN NOT NULL DEFAULT FALSE,
    parent_technique_id VARCHAR(20),
    tactic_names TEXT[] NOT NULL DEFAULT '{}',
    tactics JSONB NOT NULL DEFAULT '[]'::jsonb,
    platforms TEXT[] NOT NULL DEFAULT '{}',
    mitre_url TEXT,
    source_created_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_mitre_technique_ids_id_prefix
    ON public.mitre_technique_ids (technique_id varchar_pattern_ops);

CREATE INDEX IF NOT EXISTS ix_mitre_technique_ids_parent
    ON public.mitre_technique_ids (parent_technique_id);

CREATE INDEX IF NOT EXISTS ix_mitre_technique_ids_tactic_names
    ON public.mitre_technique_ids USING GIN (tactic_names);
