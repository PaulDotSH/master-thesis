-- ============================================================================
-- BUILD.RS SUSPICIOUS BEHAVIOR ANALYSIS
-- ============================================================================
-- Analyzes suspicious patterns detected in build.rs files.
-- Part A: Overview - how many crates exhibit each suspicious pattern
-- Part B: Crates with multiple suspicious flags (most suspicious)
-- Part C: Correlation with vulnerability findings
-- Part D: High-entropy build.rs crates (potential obfuscation)
-- ============================================================================

-- PART A: Prevalence of each suspicious build.rs pattern
SELECT 
    'Network Calls' AS pattern, COUNT(*) AS crate_count,
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM scan_results) * 100, 2) AS pct_of_scanned
FROM scan_results WHERE build_rs_network_calls = TRUE
UNION ALL
SELECT 'Link Directives', COUNT(*),
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM scan_results) * 100, 2)
FROM scan_results WHERE build_rs_has_link_directive = TRUE
UNION ALL
SELECT 'Process Spawning', COUNT(*),
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM scan_results) * 100, 2)
FROM scan_results WHERE build_rs_has_process_spawning = TRUE
UNION ALL
SELECT 'Raw IP Addresses', COUNT(*),
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM scan_results) * 100, 2)
FROM scan_results WHERE build_rs_has_raw_ip = TRUE
UNION ALL
SELECT 'Free TLDs', COUNT(*),
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM scan_results) * 100, 2)
FROM scan_results WHERE build_rs_has_free_tlds = TRUE
ORDER BY crate_count DESC;

-- PART B: Crates with most suspicious flags combined
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    (sr.build_rs_network_calls::int + 
     sr.build_rs_has_link_directive::int + 
     sr.build_rs_has_process_spawning::int + 
     sr.build_rs_has_raw_ip::int + 
     sr.build_rs_has_free_tlds::int) AS suspicious_flag_count,
    sr.build_rs_network_calls,
    sr.build_rs_has_link_directive,
    sr.build_rs_has_process_spawning,
    sr.build_rs_has_raw_ip,
    sr.build_rs_has_free_tlds,
    sr.build_rs_entropy_score,
    sr.has_executable_files
FROM scan_results sr
INNER JOIN crates c ON sr.id = c.id
WHERE sr.build_rs_network_calls = TRUE
   OR sr.build_rs_has_link_directive = TRUE
   OR sr.build_rs_has_process_spawning = TRUE
   OR sr.build_rs_has_raw_ip = TRUE
   OR sr.build_rs_has_free_tlds = TRUE
ORDER BY suspicious_flag_count DESC, sr.build_rs_entropy_score DESC
LIMIT 40;

-- PART C: Suspicious build.rs crates that also have cargo-audit vulns
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    (sr.build_rs_network_calls::int + 
     sr.build_rs_has_link_directive::int + 
     sr.build_rs_has_process_spawning::int + 
     sr.build_rs_has_raw_ip::int + 
     sr.build_rs_has_free_tlds::int) AS suspicious_flag_count,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_vuln_severity,
    sr.build_rs_entropy_score
FROM scan_results sr
INNER JOIN crates c ON sr.id = c.id
INNER JOIN cargo_audit_results car ON c.id = car.crate
WHERE sr.build_rs_network_calls = TRUE
   OR sr.build_rs_has_link_directive = TRUE
   OR sr.build_rs_has_process_spawning = TRUE
   OR sr.build_rs_has_raw_ip = TRUE
   OR sr.build_rs_has_free_tlds = TRUE
GROUP BY c.id, c.name, c.crate_downloads, sr.build_rs_network_calls,
         sr.build_rs_has_link_directive, sr.build_rs_has_process_spawning,
         sr.build_rs_has_raw_ip, sr.build_rs_has_free_tlds, sr.build_rs_entropy_score
ORDER BY suspicious_flag_count DESC, vuln_count DESC
LIMIT 30;

-- PART D: Distribution of build.rs entropy scores
SELECT 
    WIDTH_BUCKET(sr.build_rs_entropy_score, 0, 8, 20) AS entropy_bucket,
    (WIDTH_BUCKET(sr.build_rs_entropy_score, 0, 8, 20) - 1) * 0.4 AS bucket_lower,
    COUNT(*) AS crate_count
FROM scan_results sr
GROUP BY entropy_bucket
ORDER BY entropy_bucket;
