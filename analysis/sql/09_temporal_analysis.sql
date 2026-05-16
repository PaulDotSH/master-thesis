-- ============================================================================
-- TEMPORAL ANALYSIS: CRATE CREATION & VULNERABILITY PATTERNS OVER TIME
-- ============================================================================
-- Part A: Crate creation over time (by year/month)
-- Part B: Vulnerabilities by crate age (do older or newer crates have more vulns?)
-- Part C: Download velocity vs vulnerability correlation
-- ============================================================================

-- PART A: Crates created per year
SELECT 
    EXTRACT(YEAR FROM c.crate_created_at) AS creation_year,
    COUNT(*) AS crates_created,
    COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0) AS crates_with_vulns,
    ROUND(COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0)::numeric / COUNT(*) * 100, 1) AS pct_with_vulns
FROM crates c
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = c.id
) car_vulns ON TRUE
GROUP BY creation_year
ORDER BY creation_year;

-- PART B: Vulnerability prevalence by crate age bracket
SELECT 
    CASE 
        WHEN c.crate_created_at >= NOW() - INTERVAL '6 months' THEN 'Last 6 months'
        WHEN c.crate_created_at >= NOW() - INTERVAL '1 year' THEN '6 months - 1 year'
        WHEN c.crate_created_at >= NOW() - INTERVAL '2 years' THEN '1-2 years'
        WHEN c.crate_created_at >= NOW() - INTERVAL '5 years' THEN '2-5 years'
        ELSE '5+ years'
    END AS crate_age,
    COUNT(*) AS crate_count,
    COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0) AS vulnerable_count,
    ROUND(COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0)::numeric / COUNT(*) * 100, 1) AS pct_vulnerable,
    ROUND(AVG(c.crate_downloads)::numeric, 0) AS avg_downloads
FROM crates c
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = c.id
) car_vulns ON TRUE
GROUP BY crate_age
ORDER BY MIN(c.crate_created_at) DESC;

-- PART C: Downloads-per-day vs vulnerability correlation
SELECT 
    CASE 
        WHEN c.crate_downloads / GREATEST(EXTRACT(EPOCH FROM (NOW() - c.crate_created_at)) / 86400.0, 1) >= 1000 THEN 'High velocity (>=1k/d)'
        WHEN c.crate_downloads / GREATEST(EXTRACT(EPOCH FROM (NOW() - c.crate_created_at)) / 86400.0, 1) >= 100 THEN 'Medium velocity (100-1k/d)'
        WHEN c.crate_downloads / GREATEST(EXTRACT(EPOCH FROM (NOW() - c.crate_created_at)) / 86400.0, 1) >= 10 THEN 'Low velocity (10-100/d)'
        ELSE 'Very low velocity (<10/d)'
    END AS download_velocity,
    COUNT(*) AS crate_count,
    COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0) AS vulnerable_count,
    ROUND(COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0)::numeric / COUNT(*) * 100, 1) AS pct_vulnerable,
    ROUND(AVG(car_vulns.vuln_count)::numeric, 2) AS avg_vulns_per_crate
FROM crates c
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = c.id
) car_vulns ON TRUE
GROUP BY download_velocity
ORDER BY MIN(c.crate_downloads / GREATEST(EXTRACT(EPOCH FROM (NOW() - c.crate_created_at)) / 86400.0, 1)) DESC;
