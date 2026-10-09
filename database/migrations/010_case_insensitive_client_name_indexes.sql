-- Keeps case-insensitive client filters fast across all client-scoped APIs.

CREATE INDEX IF NOT EXISTS idx_ta_cio_client_name_lower_curation_actor
    ON public.threat_actor_cio_curation_summary (LOWER(client_name), curation, actor_id);

CREATE INDEX IF NOT EXISTS idx_ta_radius_client_name_lower_radius
    ON public.threat_actor_client_radius (LOWER(client_name), radius);

CREATE INDEX IF NOT EXISTS idx_etr_client_name_lower_report
    ON public.etr_client (LOWER(client_name), report_id);
