-- ============================================================================
-- EXECUTABLE FILES ANALYSIS
-- ============================================================================
-- Analyzes crates containing executable/binary files (potential malware vector).
-- Part A: Crates with executables - prevalence and overlap with other risks
-- Part B: Executables + vulnerabilities overlap
-- Part C: Executables by download count buckets (does popularity reduce risk?)
-- ============================================================================

-- PART A: Overview - executables prevalence and risk overlap
SELECT 
    has_executable_files,
    COUNT(*) AS crate_count,
    ROUND(COUNT(*)::numeric / SUM(COUNT(*)) OVER () * 100, 1) AS pct_of_total,
    ROUND(AVG(llm_malicious_score)::numeric, 2) AS avg_llm_score,
    COUNT(*) FILTER (WHERE cargo_vulns.vuln_count > 0) AS crates_with_vulns,
    COUNT(*) FILTER (WHERE secret_count > 0) AS crates_with_secrets,
    COUNT(*) FILTER (WHERE build_rs_network_calls OR build_rs_has_process_spawning 
                           OR build_rs_has_raw_ip OR build_rs_has_free_tlds) AS crates_with_suspicious_build
FROM scan_results sr
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = sr.id
) cargo_vulns ON TRUE
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS secret_count FROM gitleaks_results gl WHERE gl.crate = sr.id
) secrets ON TRUE
GROUP BY has_executable_files
ORDER BY has_executable_files;

-- PART B: Crates with executables AND vulnerabilities
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    sr.llm_malicious_score,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_vuln_severity,
    sr.build_rs_network_calls,
    sr.build_rs_has_process_spawning,
    sr.build_rs_has_raw_ip,
    sr.build_rs_has_free_tlds
FROM scan_results sr
INNER JOIN crates c ON sr.id = c.id
INNER JOIN cargo_audit_results car ON c.id = car.crate
WHERE sr.has_executable_files = TRUE
GROUP BY c.id, c.name, c.crate_downloads, sr.llm_malicious_score,
         sr.build_rs_network_calls, sr.build_rs_has_process_spawning,
         sr.build_rs_has_raw_ip, sr.build_rs_has_free_tlds
ORDER BY vuln_count DESC, max_vuln_severity DESC
LIMIT 30;

-- PART C: Executable prevalence by download count bracket
SELECT 
    CASE 
        WHEN c.crate_downloads >= 1000000 THEN '>= 1M downloads'
        WHEN c.crate_downloads >= 100000 THEN '100K - 1M'
        WHEN c.crate_downloads >= 10000 THEN '10K - 100K'
        WHEN c.crate_downloads >= 1000 THEN '1K - 10K'
        WHEN c.crate_downloads >= 100 THEN '100 - 1K'
        ELSE '< 100 downloads'
    END AS download_bracket,
    COUNT(*) AS total_crates,
    COUNT(*) FILTER (WHERE sr.has_executable_files) AS crates_with_executables,
    ROUND(COUNT(*) FILTER (WHERE sr.has_executable_files)::numeric / COUNT(*) * 100, 1) AS pct_with_executables
FROM crates c
INNER JOIN scan_results sr ON c.id = sr.id
GROUP BY download_bracket
ORDER BY MIN(c.crate_downloads) DESC;
