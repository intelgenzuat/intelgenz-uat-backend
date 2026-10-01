-- Supports the client-scoped ETR card list and fixed-batch report detail lookup.

CREATE INDEX IF NOT EXISTS idx_etr_client_name_report
    ON public.etr_client (client_name, report_id);

CREATE INDEX IF NOT EXISTS idx_etr_section_report_type_ordinal
    ON public.etr_section (report_id, section_type, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_content_section_ordinal
    ON public.etr_section_content (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_summary_section_ordinal
    ON public.etr_section_summary (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_platform_section_ordinal
    ON public.etr_section_affected_platform (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_user_section_ordinal
    ON public.etr_section_impacted_user (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_country_section_ordinal
    ON public.etr_section_affected_country (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_sector_section_ordinal
    ON public.etr_section_affected_sector (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_region_section_ordinal
    ON public.etr_section_affected_region (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_section_item_section_ordinal
    ON public.etr_section_item (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_item_address_item_ordinal
    ON public.etr_section_item_address (section_item_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_item_guidance_item_ordinal
    ON public.etr_section_item_guidance (section_item_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_item_mapping_item_ordinal
    ON public.etr_section_item_mapping (section_item_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_execution_path_section_ordinal
    ON public.etr_execution_path (section_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_execution_path_description_path_ordinal
    ON public.etr_execution_path_description (execution_path_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_execution_step_path_ordinal
    ON public.etr_execution_step (execution_path_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_execution_ttp_section_path_ordinal
    ON public.etr_execution_ttp (section_id, execution_path_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_etr_execution_ttp_step_ttp_ordinal
    ON public.etr_execution_ttp_step (execution_ttp_id, ordinal);
