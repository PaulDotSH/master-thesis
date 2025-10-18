-- ============================================================
-- QUICK REFERENCE: Most Useful Vulnerability Queries
-- ============================================================

-- Query 1: Top 10 Most Vulnerable Crates (Quick Overview)
-- ============================================================
SELECT 
    c.name,
    COUNT(car.id) AS vulnerabilities,
    MAX(car.severity) AS max_score,
    ROUND(AVG(car.severity)::numeric, 1) AS avg_score
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name
ORDER BY max_score DESC, vulnerabilities DESC
LIMIT 10;


-- Query 2: Critical Vulnerabilities (Score >= 90)
-- ============================================================
SELECT 
    c.name AS crate,
    'RUSTSEC-' || car.rustsec_id AS vuln_id,
    car.severity AS score,
    c.crate_downloads AS downloads
FROM cargo_audit_results car
INNER JOIN crates c ON car.crate = c.id
WHERE car.severity >= 90
ORDER BY car.severity DESC, c.crate_downloads DESC;


-- Query 3: Summary Statistics
-- ============================================================
SELECT 
    COUNT(DISTINCT crate) AS total_vulnerable_crates,
    COUNT(*) AS total_vulnerabilities,
    MAX(severity) AS highest_severity,
    ROUND(AVG(severity)::numeric, 2) AS avg_severity,
    COUNT(CASE WHEN severity >= 90 THEN 1 END) AS critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) AS high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) AS medium_count,
    COUNT(CASE WHEN severity < 40 THEN 1 END) AS low_count
FROM cargo_audit_results;


-- Query 4: Crates with Multiple High-Severity Issues
-- ============================================================
SELECT 
    c.name,
    COUNT(CASE WHEN car.severity >= 70 THEN 1 END) AS high_severity_count,
    COUNT(*) AS total_vulns,
    MAX(car.severity) AS max_severity,
    c.crate_downloads
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name, c.crate_downloads
HAVING COUNT(CASE WHEN car.severity >= 70 THEN 1 END) >= 2
ORDER BY high_severity_count DESC, max_severity DESC;


-- Query 5: Most Common Vulnerabilities (by RustSec ID)
-- ============================================================
SELECT 
    'RUSTSEC-' || rustsec_id AS vulnerability,
    COUNT(DISTINCT crate) AS affected_crates,
    MAX(severity) AS severity_score,
    STRING_AGG(
        (SELECT name FROM crates WHERE id = crate LIMIT 1), 
        ', ' 
    ) AS example_crates
FROM cargo_audit_results
GROUP BY rustsec_id
ORDER BY affected_crates DESC
LIMIT 20;


-- Query 6: Vulnerable Crates with Highest Download Impact
-- (Total downloads affected by vulnerabilities)
-- ============================================================
SELECT 
    c.name,
    c.crate_downloads,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_severity,
    -- Download impact: downloads * number of high-severity vulns
    c.crate_downloads * COUNT(CASE WHEN car.severity >= 70 THEN 1 END) AS download_impact
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name, c.crate_downloads
HAVING COUNT(CASE WHEN car.severity >= 70 THEN 1 END) > 0
ORDER BY download_impact DESC
LIMIT 20;


-- Query 7: Detailed Vulnerability Report for a Specific Crate
-- ============================================================
-- Replace 'serde' with the crate name you want to investigate
SELECT 
    'RUSTSEC-' || car.rustsec_id AS vulnerability_id,
    car.severity AS severity_score,
    CASE 
        WHEN car.severity >= 90 THEN 'CRITICAL'
        WHEN car.severity >= 70 THEN 'HIGH'
        WHEN car.severity >= 40 THEN 'MEDIUM'
        WHEN car.severity >= 10 THEN 'LOW'
        ELSE 'INFO'
    END AS severity_rating,
    c.name AS crate_name,
    c.repository
FROM cargo_audit_results car
INNER JOIN crates c ON car.crate = c.id
WHERE c.name = 'time'  -- Change this to the crate you want to check
ORDER BY car.severity DESC;


-- Query 8: Clean vs Vulnerable Crates Comparison
-- ============================================================
SELECT 
    'Vulnerable Crates' AS category,
    COUNT(DISTINCT car.crate) AS count
FROM cargo_audit_results car
UNION ALL
SELECT 
    'Clean Crates' AS category,
    COUNT(*) - (SELECT COUNT(DISTINCT crate) FROM cargo_audit_results) AS count
FROM crates
UNION ALL
SELECT 
    'Total Crates Analyzed' AS category,
    (SELECT COUNT(*) FROM scan_results) AS count;

