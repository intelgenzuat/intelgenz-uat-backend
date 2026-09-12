-- Supports client-specific CIO curation filtering before Intel Card pagination.

CREATE INDEX IF NOT EXISTS idx_threat_actor_cio_summary_client_actor
    ON public.threat_actor_cio_curation_summary (client_name, actor_id);
