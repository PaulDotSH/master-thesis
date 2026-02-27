-- Add build.rs analysis columns to scan_results table
-- These flags detect potentially suspicious patterns in build.rs files

ALTER TABLE scan_results
    -- Network calls flag: detects common Rust network libraries usage
    -- Matches: reqwest, hyper, curl, ureq, attohttpc, surf, isahc, minreq, etc.
    ADD COLUMN build_rs_network_calls BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Link directive flag: detects #[link] or println!("cargo:rustc-link")
    -- Regex pattern: #\[link\]|cargo:rustc-link-lib|cargo:rustc-link-search
    ADD COLUMN build_rs_has_link_directive BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Entropy score: measures randomness/obfuscation in build.rs code (0.0 - 8.0)
    -- Higher entropy may indicate obfuscated or encrypted code
    ADD COLUMN build_rs_entropy_score REAL NOT NULL DEFAULT 0.0,
    
    -- Process spawning flag: detects Command::new, process::Command, std::process
    -- Regex pattern: Command::new|process::Command|std::process|exec|spawn
    ADD COLUMN build_rs_has_process_spawning BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Raw IP addresses flag: detects non-local IP addresses in code
    -- Regex pattern: \b(?!127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
    -- Excludes: 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x (local/private ranges)
    ADD COLUMN build_rs_has_raw_ip BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Free TLDs flag: detects potentially suspicious free domain TLDs
    -- Regex pattern: \.(tk|ml|ga|cf|gq|xyz|top|work|click|link|host)\b
    ADD COLUMN build_rs_has_free_tlds BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- General entropy score for scan results (Shannon entropy of crate source)
    ADD COLUMN entropy_score REAL NOT NULL DEFAULT 0.0;

-- Add comments on the columns for documentation
COMMENT ON COLUMN scan_results.build_rs_network_calls IS 'Detects network library usage in build.rs (reqwest, hyper, curl, etc.)';
COMMENT ON COLUMN scan_results.build_rs_has_link_directive IS 'Detects link directives in build.rs (#[link], cargo:rustc-link-*)';
COMMENT ON COLUMN scan_results.build_rs_entropy_score IS 'Shannon entropy score of build.rs content (0.0-8.0, higher = more random)';
COMMENT ON COLUMN scan_results.build_rs_has_process_spawning IS 'Detects process spawning in build.rs (Command::new, exec, spawn)';
COMMENT ON COLUMN scan_results.build_rs_has_raw_ip IS 'Detects non-local raw IP addresses in build.rs';
COMMENT ON COLUMN scan_results.build_rs_has_free_tlds IS 'Detects free/suspicious TLDs in build.rs (.tk, .ml, .xyz, etc.)';
COMMENT ON COLUMN scan_results.entropy_score IS 'General entropy score for the entire crate source code';
