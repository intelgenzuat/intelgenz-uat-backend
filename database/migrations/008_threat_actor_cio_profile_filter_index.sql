-- Supports exact Capability, Intent, and Opportunity filtering per client.

CREATE INDEX IF NOT EXISTS idx_threat_actor_cio_summary_profile_lookup
    ON public.threat_actor_cio_curation_summary (
        client_name,
        (COALESCE(LOWER(capability), '') = 'yes'),
        (COALESCE(LOWER(intent), '') = 'yes'),
        (COALESCE(LOWER(opportunity), '') = 'yes'),
        actor_id
    );
