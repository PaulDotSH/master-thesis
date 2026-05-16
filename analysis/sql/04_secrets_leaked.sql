-- ============================================================================
-- SECRETS & CREDENTIAL LEAKAGE (GITLEAKS ANALYSIS)
-- ============================================================================
-- Analyzes leaked secrets found in crate source code via Gitleaks.
-- Part A: Crates with the most secrets leaked
-- Part B: Distribution of secret types (rule_id frequency)
-- Part C: Entropy statistics (high entropy = harder to detect, more obfuscated)
-- Part D: Crates with secrets AND vulnerabilities (compound risk)
-- ============================================================================

-- PART A: Crates with most leaked secrets
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(gl.id) AS secrets_count,
    ROUND(AVG(gl.entropy)::numeric, 2) AS avg_entropy,
    MAX(gl.entropy) AS max_entropy,
    STRING_AGG(DISTINCT gl.rule_id, ', ' ORDER BY gl.rule_id) AS secret_types
FROM crates c
INNER JOIN gitleaks_results gl ON c.id = gl.crate
GROUP BY c.id, c.name, c.crate_downloads
ORDER BY secrets_count DESC
LIMIT 30;

-- PART B: Distribution of secret types
SELECT 
    gl.rule_id AS secret_type,
    COUNT(*) AS occurrence_count,
    COUNT(DISTINCT gl.crate) AS affected_crates,
    ROUND(AVG(gl.entropy)::numeric, 2) AS avg_entropy,
    ROUND((COUNT(*)::numeric / SUM(COUNT(*)) OVER ()) * 100, 1) AS pct_of_all_secrets
FROM gitleaks_results gl
GROUP BY gl.rule_id
ORDER BY occurrence_count DESC
LIMIT 30;

-- PART C: Overall gitleaks summary statistics
SELECT 
    COUNT(*) AS total_secrets_found,
    COUNT(DISTINCT crate) AS crates_with_secrets,
    COUNT(DISTINCT rule_id) AS unique_secret_types,
    ROUND(AVG(entropy)::numeric, 2) AS avg_entropy,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY entropy) AS median_entropy,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY entropy) AS p95_entropy,
    MAX(entropy) AS max_entropy
FROM gitleaks_results;

-- PART D: Crates with BOTH secrets leaked AND cargo-audit vulnerabilities
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(DISTINCT gl.id) AS secrets_count,
    COUNT(DISTINCT car.id) AS vuln_count,
    MAX(car.severity) AS max_vuln_severity,
    STRING_AGG(DISTINCT gl.rule_id, ', ' ORDER BY gl.rule_id) AS secret_types,
    STRING_AGG(DISTINCT 'RUSTSEC-' || car.rustsec_id, ', ') AS vuln_advisories
FROM crates c
INNER JOIN gitleaks_results gl ON c.id = gl.crate
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name, c.crate_downloads
ORDER BY secrets_count DESC, vuln_count DESC
LIMIT 30;
