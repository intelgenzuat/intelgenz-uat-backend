-- Supports fast all-technique threat actor matching for CIO assessments.

CREATE INDEX IF NOT EXISTS idx_ta_mitre_technique_actor
    ON public.ta_mitre_attack (technique_id, actor_id);
