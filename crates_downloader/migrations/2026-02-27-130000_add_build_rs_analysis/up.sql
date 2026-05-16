ALTER TABLE scan_results
    ADD COLUMN build_rs_network_calls BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN build_rs_has_link_directive BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN build_rs_entropy_score REAL NOT NULL DEFAULT 0.0,
    ADD COLUMN build_rs_has_process_spawning BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN build_rs_has_raw_ip BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN build_rs_has_free_tlds BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN entropy_score REAL NOT NULL DEFAULT 0.0;

COMMENT ON COLUMN scan_results.build_rs_network_calls IS 'Detects network library usage in build.rs (reqwest, hyper, curl, etc.)';
COMMENT ON COLUMN scan_results.build_rs_has_link_directive IS 'Detects link directives in build.rs (#[link], cargo:rustc-link-*)';
COMMENT ON COLUMN scan_results.build_rs_entropy_score IS 'Shannon entropy score of build.rs content (0.0-8.0, higher = more random)';
COMMENT ON COLUMN scan_results.build_rs_has_process_spawning IS 'Detects process spawning in build.rs (Command::new, exec, spawn)';
COMMENT ON COLUMN scan_results.build_rs_has_raw_ip IS 'Detects non-local raw IP addresses in build.rs';
COMMENT ON COLUMN scan_results.build_rs_has_free_tlds IS 'Detects free/suspicious TLDs in build.rs (.tk, .ml, .xyz, etc.)';
COMMENT ON COLUMN scan_results.entropy_score IS 'General entropy score for the entire crate source code';
