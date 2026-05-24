-- ============================================================================
-- ECOSYSTEM-WIDE VULNERABILITY & DEPENDENCY STATISTICS
-- ============================================================================
-- Computes statistics across crates in the ecosystem.
-- Uses successfully scanned crates (llm_malicious_score != -1) as the
-- denominator for percentage calculations, since only scanned crates
-- have known vulnerability status.
--   - Total crates, scanned crates, failed scans
--   - Crates with vulns, percentage of vulnerable crates (of scanned)
--   - Max, mean, and median vulns per crate (of scanned)
--   - Mean and median number of dependencies per crate (of scanned)
--   - Vuln count distribution (histogram buckets)
--   - Dependency count distribution (histogram buckets)
-- ============================================================================

-- PART A: Ecosystem-wide summary statistics (one row)
WITH scanned_vulns AS (
    SELECT c.id, COUNT(car.id) AS cnt
    FROM crates c
    INNER JOIN scan_results sr ON c.id = sr.id AND sr.llm_malicious_score != -1
    LEFT JOIN cargo_audit_results car ON c.id = car.crate
    GROUP BY c.id
),
scanned_deps AS (
    SELECT c.id, COUNT(d.dependency_id) AS cnt
    FROM crates c
    INNER JOIN scan_results sr ON c.id = sr.id AND sr.llm_malicious_score != -1
    LEFT JOIN dependencies d ON c.id = d.crate_id
    GROUP BY c.id
),
all_crates AS (
    SELECT COUNT(*) AS total FROM crates
),
scan_status AS (
    SELECT
        COUNT(*) AS crates_in_scan_results,
        COUNT(*) FILTER (WHERE llm_malicious_score = -1) AS failed_scans,
        COUNT(*) FILTER (WHERE llm_malicious_score != -1) AS successful_scans
    FROM scan_results
)
SELECT
    (SELECT total FROM all_crates) AS total_crates,
    (SELECT crates_in_scan_results FROM scan_status) AS in_scan_results,
    (SELECT successful_scans FROM scan_status) AS successfully_scanned,
    (SELECT failed_scans FROM scan_status) AS failed_scans,
    SUM(CASE WHEN sv.cnt > 0 THEN 1 ELSE 0 END) AS crates_with_vulns,
    ROUND(SUM(CASE WHEN sv.cnt > 0 THEN 1 ELSE 0 END)::numeric / COUNT(*) * 100, 2) AS pct_vuln_crates,
    MAX(sv.cnt) AS max_vulns_in_crate,
    ROUND(AVG(sv.cnt)::numeric, 2) AS mean_vulns_per_crate,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY sv.cnt) AS median_vulns_per_crate,
    ROUND(AVG(sd.cnt)::numeric, 2) AS mean_deps_per_crate,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY sd.cnt) AS median_deps_per_crate
FROM scanned_vulns sv
JOIN scanned_deps sd ON sv.id = sd.id;

-- PART B: Vulnerability count distribution (only scanned crates)
SELECT
    CASE
        WHEN vuln_count >= 10 THEN '10+'
        WHEN vuln_count >= 5 THEN '5-9'
        WHEN vuln_count >= 3 THEN '3-4'
        WHEN vuln_count = 2 THEN '2'
        WHEN vuln_count = 1 THEN '1'
        ELSE '0'
    END AS vuln_count_bracket,
    COUNT(*) AS crate_count
FROM (
    SELECT COUNT(car.id) AS vuln_count
    FROM crates c
    INNER JOIN scan_results sr ON c.id = sr.id AND sr.llm_malicious_score != -1
    LEFT JOIN cargo_audit_results car ON c.id = car.crate
    GROUP BY c.id
) sub
GROUP BY vuln_count_bracket
ORDER BY MIN(vuln_count);

-- PART C: Dependency count distribution (only scanned crates)
SELECT
    CASE
        WHEN dep_count >= 200 THEN '200+'
        WHEN dep_count >= 100 THEN '100-199'
        WHEN dep_count >= 50 THEN '50-99'
        WHEN dep_count >= 20 THEN '20-49'
        WHEN dep_count >= 10 THEN '10-19'
        WHEN dep_count >= 5 THEN '5-9'
        WHEN dep_count >= 1 THEN '1-4'
        ELSE '0'
    END AS dep_count_bracket,
    COUNT(*) AS crate_count
FROM (
    SELECT COUNT(d.dependency_id) AS dep_count
    FROM crates c
    INNER JOIN scan_results sr ON c.id = sr.id AND sr.llm_malicious_score != -1
    LEFT JOIN dependencies d ON c.id = d.crate_id
    GROUP BY c.id
) sub
GROUP BY dep_count_bracket
ORDER BY MIN(dep_count);

-- PART D: Vulnerability concentration (top N crates hold X% of all vulns)
WITH vuln_counts AS (
    SELECT c.name, COUNT(car.id) AS vuln_count
    FROM crates c
    INNER JOIN cargo_audit_results car ON c.id = car.crate
    GROUP BY c.id, c.name
),
ranked AS (
    SELECT
        vuln_count,
        ROW_NUMBER() OVER (ORDER BY vuln_count DESC) AS rn,
        SUM(vuln_count) OVER () AS grand_total
    FROM vuln_counts
)
SELECT 'Top 10 crates' AS concentration_bucket,
    COALESCE(SUM(vuln_count), 0) AS vulns_in_bucket,
    ROUND(COALESCE(SUM(vuln_count)::numeric / NULLIF(MAX(grand_total), 0) * 100, 0), 1) AS pct_of_all_vulns
FROM ranked WHERE rn <= 10
UNION ALL
SELECT 'Top 50 crates',
    COALESCE(SUM(vuln_count), 0),
    ROUND(COALESCE(SUM(vuln_count)::numeric / NULLIF(MAX(grand_total), 0) * 100, 0), 1)
FROM ranked WHERE rn <= 50
UNION ALL
SELECT 'Top 100 crates',
    COALESCE(SUM(vuln_count), 0),
    ROUND(COALESCE(SUM(vuln_count)::numeric / NULLIF(MAX(grand_total), 0) * 100, 0), 1)
FROM ranked WHERE rn <= 100
UNION ALL
SELECT 'Remaining crates',
    COALESCE(SUM(vuln_count), 0),
    ROUND(COALESCE(SUM(vuln_count)::numeric / NULLIF(MAX(grand_total), 0) * 100, 0), 1)
FROM ranked WHERE rn > 100;
