-- Stores CIO curation assessments and supporting evidence for known threat actors.

CREATE TABLE IF NOT EXISTS public.threat_actor_cio_question_reference (
    assessment TEXT NOT NULL,
    question_id TEXT NOT NULL,
    question TEXT NOT NULL,
    PRIMARY KEY (assessment, question_id)
);

CREATE TABLE IF NOT EXISTS public.threat_actor_cio_curation_summary (
    actor_id BIGINT NOT NULL REFERENCES public.threat_actor(actor_id) ON DELETE CASCADE,
    client_name TEXT NOT NULL,
    capability TEXT NOT NULL,
    intent TEXT NOT NULL,
    opportunity TEXT NOT NULL,
    curation TEXT NOT NULL,
    PRIMARY KEY (actor_id, client_name)
);

CREATE TABLE IF NOT EXISTS public.threat_actor_cio_evidence_detail (
    actor_id BIGINT NOT NULL REFERENCES public.threat_actor(actor_id) ON DELETE CASCADE,
    client_name TEXT NOT NULL,
    assessment TEXT NOT NULL,
    question_id TEXT NOT NULL,
    answer TEXT NOT NULL,
    actor_evidence TEXT NOT NULL,
    client_evidence TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (actor_id, client_name, assessment, question_id),
    FOREIGN KEY (assessment, question_id)
        REFERENCES public.threat_actor_cio_question_reference (assessment, question_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_actor_cio_summary_client_curation
    ON public.threat_actor_cio_curation_summary (client_name, curation);

CREATE INDEX IF NOT EXISTS idx_threat_actor_cio_evidence_actor_client
    ON public.threat_actor_cio_evidence_detail (actor_id, client_name);
