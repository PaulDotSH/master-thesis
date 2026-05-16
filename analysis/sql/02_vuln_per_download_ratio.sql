-- ============================================================================
-- VULNERABILITY-TO-DOWNLOAD RATIO (MOST VULNERABLE PER DOWNLOAD)
-- ============================================================================
-- Identifies crates that are highly vulnerable relative to their download count.
-- A high ratio suggests either abandoned crates with unpatched vulns or 
-- potentially malicious crates that have vulns but very few real users.
-- Ratio = vuln_count / log10(crate_downloads + 1) to avoid division by zero
-- and to make the metric scale reasonably across magnitudes of popularity.
-- ============================================================================

SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_severity,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity,
    ROUND(
        (COUNT(car.id)::numeric * AVG(car.severity)) 
        / GREATEST(LN(c.crate_downloads + 1)::numeric, 0.01),
    2) AS vuln_per_log_download_ratio,
    STRING_AGG('RUSTSEC-' || car.rustsec_id, ', ' ORDER BY car.severity DESC) AS advisories
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY c.id, c.name, c.crate_downloads
ORDER BY vuln_per_log_download_ratio DESC
LIMIT 30;
