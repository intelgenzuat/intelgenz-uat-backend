-- Stores a client-specific radius assessment for each known threat actor.
-- Radius values come from threat_actor_radius.xlsx and are scored from 0 to 5.

CREATE TABLE IF NOT EXISTS public.threat_actor_client_radius (
    actor_id BIGINT NOT NULL REFERENCES public.threat_actor(actor_id) ON DELETE CASCADE,
    client_name TEXT NOT NULL,
    radius NUMERIC(4, 2) NOT NULL CHECK (radius >= 0 AND radius <= 5),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (actor_id, client_name)
);

CREATE INDEX IF NOT EXISTS idx_threat_actor_client_radius_client_score
    ON public.threat_actor_client_radius (client_name, radius DESC);
