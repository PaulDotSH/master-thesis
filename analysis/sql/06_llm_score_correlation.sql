-- ============================================================================
-- LLM MALICIOUS SCORE CORRELATION ANALYSIS
-- ============================================================================
-- Compares LLM-based maliciousness scores against objective findings
-- (cargo-audit, gitleaks, build.rs flags) to evaluate LLM effectiveness.
-- Part A: LLM score distribution
-- Part B: Correlation - do high LLM scores predict cargo-audit findings?
-- Part C: High LLM score but no cargo-audit vulns (false positives?)
-- Part D: Low LLM score but many vulns (false negatives?)
-- ============================================================================

-- PART A: LLM malicious score distribution
SELECT 
    WIDTH_BUCKET(sr.llm_malicious_score, 0, 100, 20) AS score_bucket,
    (WIDTH_BUCKET(sr.llm_malicious_score, 0, 100, 20) - 1) * 5 AS bucket_lower,
    COUNT(*) AS crate_count,
    COUNT(CASE WHEN cargo_vulns.vuln_count > 0 THEN 1 END) AS crates_with_vulns,
    COUNT(CASE WHEN secrets.secret_count > 0 THEN 1 END) AS crates_with_secrets
FROM scan_results sr
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = sr.id
) cargo_vulns ON TRUE
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS secret_count FROM gitleaks_results gl WHERE gl.crate = sr.id
) secrets ON TRUE
GROUP BY score_bucket
ORDER BY score_bucket;

-- PART B: High LLM score (>=70) crates with their actual findings
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    sr.llm_malicious_score,
    COALESCE(vuln_stats.vuln_count, 0) AS cargo_audit_vulns,
    COALESCE(vuln_stats.max_severity, 0) AS max_vuln_severity,
    COALESCE(secret_stats.secret_count, 0) AS gitleaks_secrets,
    sr.has_executable_files,
    sr.build_rs_network_calls OR sr.build_rs_has_process_spawning 
        OR sr.build_rs_has_raw_ip OR sr.build_rs_has_free_tlds AS has_suspicious_build_rs
FROM scan_results sr
INNER JOIN crates c ON sr.id = c.id
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count, MAX(severity) AS max_severity 
    FROM cargo_audit_results car WHERE car.crate = sr.id
) vuln_stats ON TRUE
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS secret_count
    FROM gitleaks_results gl WHERE gl.crate = sr.id
) secret_stats ON TRUE
WHERE sr.llm_malicious_score >= 70
ORDER BY sr.llm_malicious_score DESC, c.crate_downloads DESC
LIMIT 30;

-- PART C: LLM vs Cargo-Audit agreement matrix
SELECT 
    CASE 
        WHEN sr.llm_malicious_score >= 75 THEN 'LLM: Malicious (>=75)'
        WHEN sr.llm_malicious_score >= 50 THEN 'LLM: Suspicious (50-74)'
        WHEN sr.llm_malicious_score >= 25 THEN 'LLM: Low suspicion (25-49)'
        ELSE 'LLM: Benign (<25)'
    END AS llm_category,
    CASE WHEN car_vuln.vuln_count > 0 THEN 'Has cargo-audit vulns' ELSE 'No cargo-audit vulns' END AS vuln_status,
    COUNT(*) AS crate_count
FROM scan_results sr
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = sr.id
) car_vuln ON TRUE
GROUP BY 
    CASE 
        WHEN sr.llm_malicious_score >= 75 THEN 'LLM: Malicious (>=75)'
        WHEN sr.llm_malicious_score >= 50 THEN 'LLM: Suspicious (50-74)'
        WHEN sr.llm_malicious_score >= 25 THEN 'LLM: Low suspicion (25-49)'
        ELSE 'LLM: Benign (<25)'
    END,
    CASE WHEN car_vuln.vuln_count > 0 THEN 'Has cargo-audit vulns' ELSE 'No cargo-audit vulns' END
ORDER BY llm_category, vuln_status;

-- PART D: Summary stats
SELECT 
    COUNT(*) AS total_scanned,
    COUNT(*) FILTER (WHERE llm_malicious_score >= 75) AS flagged_by_llm,
    ROUND(AVG(CASE WHEN car_vuln.vuln_count > 0 THEN llm_malicious_score END)::numeric, 2) AS avg_llm_score_with_vulns,
    ROUND(AVG(CASE WHEN car_vuln.vuln_count = 0 THEN llm_malicious_score END)::numeric, 2) AS avg_llm_score_without_vulns,
    ROUND(AVG(llm_malicious_score)::numeric, 2) AS overall_avg_llm_score
FROM scan_results sr
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = sr.id
) car_vuln ON TRUE;
