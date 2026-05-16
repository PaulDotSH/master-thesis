-- ============================================================================
-- DEPENDENCY NETWORK & ECOSYSTEM IMPACT ANALYSIS
-- ============================================================================
-- Part A: Most depended-upon crates (centrality in the ecosystem)
-- Part B: Most depended-upon VULNERABLE crates (highest ecosystem risk)
-- Part C: Dependency chain statistics (how many crates use how many deps)
-- Part D: Crates that depend on the most other crates
-- ============================================================================

-- PART A: Top most depended-upon crates (highest in-degree centrality)
SELECT 
    c.name AS dependency_name,
    c.crate_downloads,
    COUNT(DISTINCT d.crate_id) AS dependents_count,
    CASE WHEN car_vulns.vuln_count > 0 THEN 'YES' ELSE 'NO' END AS has_vulnerabilities,
    COALESCE(car_vulns.vuln_count, 0) AS vuln_count,
    COALESCE(car_vulns.max_severity, 0) AS max_vuln_severity
FROM crates c
INNER JOIN dependencies d ON c.id = d.dependency_id
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count, MAX(severity) AS max_severity
    FROM cargo_audit_results car WHERE car.crate = c.id
) car_vulns ON TRUE
GROUP BY c.id, c.name, c.crate_downloads, car_vulns.vuln_count, car_vulns.max_severity
ORDER BY dependents_count DESC
LIMIT 30;

-- PART B: Most depended-upon vulnerable crates (highest ecosystem risk)
SELECT 
    c.name AS dependency_name,
    c.crate_downloads,
    COUNT(DISTINCT d.crate_id) AS dependents_count,
    car_vulns.vuln_count,
    car_vulns.max_severity,
    ROUND((COUNT(DISTINCT d.crate_id) * car_vulns.vuln_count * COALESCE(car_vulns.max_severity, 0))::numeric, 0) AS ecosystem_risk_score,
    STRING_AGG(DISTINCT 'RUSTSEC-' || car.rustsec_id, ', ') AS advisories
FROM crates c
INNER JOIN dependencies d ON c.id = d.dependency_id
INNER JOIN cargo_audit_results car ON c.id = car.crate
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count, MAX(severity) AS max_severity
    FROM cargo_audit_results car2 WHERE car2.crate = c.id
) car_vulns ON TRUE
GROUP BY c.id, c.name, c.crate_downloads, car_vulns.vuln_count, car_vulns.max_severity
ORDER BY ecosystem_risk_score DESC
LIMIT 30;

-- PART C: Dependency count distribution
SELECT 
    CASE 
        WHEN dep_counts.dep_count >= 200 THEN '200+ dependencies'
        WHEN dep_counts.dep_count >= 100 THEN '100-199'
        WHEN dep_counts.dep_count >= 50 THEN '50-99'
        WHEN dep_counts.dep_count >= 20 THEN '20-49'
        WHEN dep_counts.dep_count >= 10 THEN '10-19'
        WHEN dep_counts.dep_count >= 5 THEN '5-9'
        WHEN dep_counts.dep_count >= 1 THEN '1-4'
        ELSE '0 dependencies'
    END AS dep_count_bracket,
    COUNT(*) AS crate_count,
    ROUND(COUNT(*)::numeric / SUM(COUNT(*)) OVER () * 100, 1) AS pct_of_total
FROM (
    SELECT c.id, COUNT(d.dependency_id) AS dep_count
    FROM crates c
    LEFT JOIN dependencies d ON c.id = d.crate_id
    GROUP BY c.id
) dep_counts
GROUP BY dep_count_bracket
ORDER BY MIN(dep_counts.dep_count);

-- PART D: Crates with the most dependencies (highest out-degree)
SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(d.dependency_id) AS dependency_count,
    COALESCE(vuln_stats.vuln_count, 0) AS direct_vulns,
    COALESCE(vuln_stats.max_severity, 0) AS max_vuln_severity
FROM crates c
INNER JOIN dependencies d ON c.id = d.crate_id
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count, MAX(severity) AS max_severity
    FROM cargo_audit_results car WHERE car.crate = c.id
) vuln_stats ON TRUE
GROUP BY c.id, c.name, c.crate_downloads, vuln_stats.vuln_count, vuln_stats.max_severity
ORDER BY dependency_count DESC
LIMIT 30;
