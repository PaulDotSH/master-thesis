-- Remove build.rs analysis columns from scan_results table

ALTER TABLE scan_results
    DROP COLUMN IF EXISTS build_rs_network_calls,
    DROP COLUMN IF EXISTS build_rs_has_link_directive,
    DROP COLUMN IF EXISTS build_rs_entropy_score,
    DROP COLUMN IF EXISTS build_rs_has_process_spawning,
    DROP COLUMN IF EXISTS build_rs_has_raw_ip,
    DROP COLUMN IF EXISTS build_rs_has_free_tlds,
    DROP COLUMN IF EXISTS entropy_score;
