-- ============================================================================
-- MOST VULNERABLE CRATES (DIRECT VULNERABILITIES)
-- ============================================================================
-- Crates with the highest number and severity of direct cargo-audit findings.
-- Ordered by a weighted risk score combining vuln count and severity.
-- ============================================================================

SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_severity,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity,
    ROUND((COUNT(car.id) * AVG(car.severity) + MAX(car.severity) / 10.0)::numeric, 2) AS risk_score,
    STRING_AGG('RUSTSEC-' || car.rustsec_id, ', ' ORDER BY car.severity DESC) AS advisories
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name, c.crate_downloads
ORDER BY risk_score DESC
LIMIT 30;
