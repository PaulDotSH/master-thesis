-- ============================================================================
-- ECOSYSTEM-LEVEL SECURITY OVERVIEW
-- ============================================================================
-- High-level statistics about the Rust crate ecosystem security posture.
-- Part A: Key metrics (total crates, scanned, vulnerable, etc.)
-- Part B: Vulnerability severity distribution
-- Part C: Most common RustSec advisories
-- Part D: Worker/analysis performance statistics
-- ============================================================================

-- PART A: Key ecosystem metrics
SELECT 'Total crates in database' AS metric, COUNT(*)::text AS value FROM crates
UNION ALL
SELECT 'Crates with scan results', COUNT(*)::text FROM scan_results
UNION ALL
SELECT 'Crates with cargo-audit vulns', COUNT(DISTINCT crate)::text FROM cargo_audit_results
UNION ALL
SELECT 'Crates with leaked secrets', COUNT(DISTINCT crate)::text FROM gitleaks_results
UNION ALL
SELECT 'Crates with executable files', COUNT(*)::text FROM scan_results WHERE has_executable_files = TRUE
UNION ALL
SELECT 'Crates with suspicious build.rs', COUNT(*)::text FROM scan_results WHERE build_rs_network_calls OR build_rs_has_process_spawning OR build_rs_has_raw_ip OR build_rs_has_free_tlds
UNION ALL
SELECT 'Crates with high LLM score (>=75)', COUNT(*)::text FROM scan_results WHERE llm_malicious_score >= 75
UNION ALL
SELECT 'Total dependency relationships', COUNT(*)::text FROM dependencies
UNION ALL
SELECT 'Total typosquat pairs detected', COUNT(*)::text FROM typosquat_results
UNION ALL
SELECT 'Total secrets found (gitleaks)', COUNT(*)::text FROM gitleaks_results
UNION ALL
SELECT 'Total cargo-audit findings', COUNT(*)::text FROM cargo_audit_results
UNION ALL
SELECT 'Unique RustSec advisories', COUNT(DISTINCT rustsec_id)::text FROM cargo_audit_results
UNION ALL
SELECT 'Total analysis metrics recorded', COUNT(*)::text FROM analysis_metrics;

-- PART B: Vulnerability severity distribution
SELECT 
    CASE 
        WHEN severity >= 90 THEN 'Critical (9.0-10.0)'
        WHEN severity >= 70 THEN 'High (7.0-8.9)'
        WHEN severity >= 40 THEN 'Medium (4.0-6.9)'
        WHEN severity >= 10 THEN 'Low (1.0-3.9)'
        ELSE 'Info (<1.0)'
    END AS severity_level,
    COUNT(*) AS finding_count,
    COUNT(DISTINCT crate) AS affected_crates,
    ROUND(COUNT(*)::numeric / SUM(COUNT(*)) OVER () * 100, 1) AS pct_of_total,
    ROUND(AVG(severity)::numeric, 2) AS avg_severity_in_level
FROM cargo_audit_results
GROUP BY severity_level
ORDER BY MIN(severity) DESC;

-- PART C: Most common RustSec advisories
SELECT 
    'RUSTSEC-' || rustsec_id AS advisory,
    COUNT(*) AS occurrences,
    COUNT(DISTINCT crate) AS affected_crates,
    ROUND(AVG(severity)::numeric, 2) AS avg_severity
FROM cargo_audit_results
GROUP BY rustsec_id
ORDER BY occurrences DESC
LIMIT 20;

-- PART D: Analysis metrics (worker performance summary)
SELECT 
    COUNT(*) AS total_analyses,
    ROUND(AVG(total_duration_ms)::numeric, 0) AS avg_total_ms,
    ROUND(AVG(total_duration_ms)::numeric / 1000, 1) AS avg_total_sec,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY total_duration_ms) AS median_total_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY total_duration_ms) AS p95_total_ms,
    MAX(total_duration_ms) AS max_total_ms,
    ROUND(AVG(COALESCE(cargo_audit_duration_ms, 0))::numeric, 0) AS avg_cargo_audit_ms,
    ROUND(AVG(COALESCE(gitleaks_duration_ms, 0))::numeric, 0) AS avg_gitleaks_ms,
    ROUND(AVG(COALESCE(build_rs_analysis_duration_ms, 0))::numeric, 0) AS avg_build_rs_ms,
    ROUND(AVG(COALESCE(llm_analysis_duration_ms, 0))::numeric, 0) AS avg_llm_ms,
    ROUND(AVG(COALESCE(download_duration_ms, 0))::numeric, 0) AS avg_download_ms
FROM analysis_metrics;

-- PART E: Crates with suspicious build.rs AND executable files AND vulns (compound risk)
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    sr.llm_malicious_score,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_vuln_severity,
    COUNT(gl.id) AS secrets_count,
    sr.build_rs_network_calls,
    sr.build_rs_has_process_spawning,
    sr.build_rs_has_raw_ip,
    sr.build_rs_has_free_tlds
FROM scan_results sr
INNER JOIN crates c ON sr.id = c.id
INNER JOIN cargo_audit_results car ON c.id = car.crate
LEFT JOIN gitleaks_results gl ON c.id = gl.crate
WHERE sr.has_executable_files = TRUE
  AND (sr.build_rs_network_calls OR sr.build_rs_has_process_spawning 
       OR sr.build_rs_has_raw_ip OR sr.build_rs_has_free_tlds)
GROUP BY c.id, c.name, c.crate_downloads, sr.llm_malicious_score,
         sr.build_rs_network_calls, sr.build_rs_has_process_spawning,
         sr.build_rs_has_raw_ip, sr.build_rs_has_free_tlds
ORDER BY vuln_count DESC, max_vuln_severity DESC
LIMIT 30;
