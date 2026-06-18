-- Shows all crates that have direct vulnerabilities in their code
-- Includes: vulnerability count, severity scores, and full details

SELECT 
    c.id AS crate_id,
    c.name AS crate_name,
    c.repository,
    c.crate_downloads,
    COUNT(car.id) AS vulnerability_count,
    MAX(car.severity) AS max_severity_score,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity_score,
    CASE 
        WHEN MAX(car.severity) >= 90 THEN 'CRITICAL'
        WHEN MAX(car.severity) >= 70 THEN 'HIGH'
        WHEN MAX(car.severity) >= 40 THEN 'MEDIUM'
        WHEN MAX(car.severity) >= 10 THEN 'LOW'
        ELSE 'INFO'
    END AS severity_rating,
    STRING_AGG(
        CONCAT('RUSTSEC-', car.rustsec_id, ' (score: ', COALESCE(car.severity::text, 'N/A'), ')'), 
        ', ' 
        ORDER BY car.severity DESC NULLS LAST
    ) AS vulnerabilities
FROM 
    crates c
    INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY 
    c.id, c.name, c.repository, c.crate_downloads
HAVING 
    COUNT(car.id) > 0
ORDER BY 
    max_severity_score DESC NULLS LAST,
    vulnerability_count DESC,
    c.crate_downloads DESC;


-- Shows each crate, its dependencies, and which dependencies have vulnerabilities
-- This reveals the dependency chain and where vulnerabilities come from

WITH crate_deps AS (
    SELECT 
        c.id,
        c.name,
        c.crate_downloads,
        COUNT(DISTINCT d.dependency_id) AS total_dependencies,
        COUNT(DISTINCT CASE WHEN car.id IS NOT NULL THEN d.dependency_id END) AS vulnerable_dependencies
    FROM crates c
    LEFT JOIN dependencies d ON c.id = d.crate_id
    LEFT JOIN cargo_audit_results car ON d.dependency_id = car.crate
    GROUP BY c.id, c.name, c.crate_downloads
),
dep_vuln_stats AS (
    -- Pre-calculate vulnerability stats for each dependency
    SELECT 
        dep_crate.id AS dep_id,
        dep_crate.name AS dep_name,
        COUNT(car.id) AS vuln_count,
        MAX(car.severity) AS max_severity
    FROM crates dep_crate
    INNER JOIN cargo_audit_results car ON dep_crate.id = car.crate
    GROUP BY dep_crate.id, dep_crate.name
)
SELECT 
    cd.name AS crate_name,
    cd.crate_downloads,
    cd.total_dependencies,
    cd.vulnerable_dependencies,
    CASE 
        WHEN cd.total_dependencies > 0 
        THEN ROUND((cd.vulnerable_dependencies::numeric / cd.total_dependencies * 100), 1)
        ELSE 0
    END AS vulnerable_dep_percentage,
    -- List all vulnerable dependencies with their stats (sorted by severity)
    STRING_AGG(
        CONCAT(dvs.dep_name, ' (', dvs.vuln_count, ' vulns, max: ', dvs.max_severity, ')'), 
        ', '
        ORDER BY dvs.max_severity DESC, dvs.vuln_count DESC
    ) AS vulnerable_dependencies_list
FROM crate_deps cd
JOIN dependencies d ON cd.id = d.crate_id
JOIN dep_vuln_stats dvs ON d.dependency_id = dvs.dep_id
GROUP BY cd.id, cd.name, cd.crate_downloads, cd.total_dependencies, cd.vulnerable_dependencies
HAVING cd.vulnerable_dependencies > 0  -- Only show crates that have vulnerable deps
ORDER BY cd.vulnerable_dependencies DESC, vulnerable_dep_percentage DESC
LIMIT 50;


-- Shows which dependencies are most problematic (have vulnerabilities and are used by many crates)

WITH ranked_dependents AS (
    SELECT 
        d.dependency_id,
        dependent.name AS dependent_name,
        ROW_NUMBER() OVER (PARTITION BY d.dependency_id ORDER BY dependent.crate_downloads DESC) as row_num
    FROM dependencies d
    INNER JOIN crates dependent ON d.crate_id = dependent.id
)
SELECT 
    c.name AS dependency_name,
    c.repository,
    COUNT(DISTINCT car.id) AS vulnerability_count,
    MAX(car.severity) AS max_severity,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity,
    COUNT(DISTINCT d.crate_id) AS used_by_crate_count,
    -- Impact score: number of vulnerabilities * number of dependent crates
    (COUNT(DISTINCT car.id) * COUNT(DISTINCT d.crate_id)) AS impact_score,
    STRING_AGG(DISTINCT 'RUSTSEC-' || car.rustsec_id, ', ' ORDER BY 'RUSTSEC-' || car.rustsec_id) AS vulnerabilities,
    -- Show top 5 crates that depend on this
    (
        SELECT STRING_AGG(dependent_name, ', ')
        FROM ranked_dependents rd
        WHERE rd.dependency_id = c.id AND rd.row_num <= 5
    ) AS example_dependents
FROM crates c
INNER JOIN cargo_audit_results car ON c.id = car.crate
INNER JOIN dependencies d ON c.id = d.dependency_id
GROUP BY c.id, c.name, c.repository
HAVING COUNT(DISTINCT d.crate_id) > 0
ORDER BY impact_score DESC, max_severity DESC
LIMIT 30;


-- Combines vulnerability count and severity for a comprehensive risk assessment
-- Risk Score = (vuln_count * avg_severity) + (max_severity / 10)

SELECT 
    c.id AS crate_id,
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_severity,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity,
    ROUND((COUNT(car.id) * AVG(car.severity) + MAX(car.severity) / 10.0)::numeric, 2) AS risk_score,
    CASE 
        WHEN MAX(car.severity) >= 90 THEN 'CRITICAL'
        WHEN MAX(car.severity) >= 70 THEN 'HIGH'
        WHEN MAX(car.severity) >= 40 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity_rating,
    STRING_AGG('RUSTSEC-' || car.rustsec_id, ', ' ORDER BY car.severity DESC) AS rustsec_ids
FROM 
    crates c
    INNER JOIN cargo_audit_results car ON c.id = car.crate
GROUP BY 
    c.id, c.name, c.crate_downloads
ORDER BY 
    risk_score DESC,
    max_severity DESC
LIMIT 20;


-- Shows all critical and high severity vulnerabilities (CVSS >= 7.0)

WITH ranked_dependents_high_sev AS (
    SELECT 
        car.id AS vuln_id,
        dependent.name AS dependent_name,
        ROW_NUMBER() OVER (PARTITION BY car.id ORDER BY dependent.crate_downloads DESC NULLS LAST) as row_num
    FROM cargo_audit_results car
    INNER JOIN crates c ON car.crate = c.id
    LEFT JOIN dependencies d ON c.id = d.dependency_id
    LEFT JOIN crates dependent ON d.crate_id = dependent.id
    WHERE car.severity >= 70
)
SELECT 
    c.name AS vulnerable_crate,
    'RUSTSEC-' || car.rustsec_id AS vulnerability_id,
    car.severity AS severity_score,
    CASE 
        WHEN car.severity >= 90 THEN 'CRITICAL'
        WHEN car.severity >= 70 THEN 'HIGH'
        WHEN car.severity >= 40 THEN 'MEDIUM'
        WHEN car.severity >= 10 THEN 'LOW'
        ELSE 'INFO'
    END AS severity_rating,
    c.crate_downloads AS direct_downloads,
    COUNT(DISTINCT d.crate_id) AS used_as_dependency_by,
    c.crate_downloads + COUNT(DISTINCT d.crate_id) AS total_exposure,
    c.repository,
    (
        SELECT STRING_AGG(dependent_name, ', ')
        FROM ranked_dependents_high_sev rd
        WHERE rd.vuln_id = car.id AND rd.row_num <= 10
    ) AS example_dependents
FROM 
    cargo_audit_results car
    INNER JOIN crates c ON car.crate = c.id
    LEFT JOIN dependencies d ON c.id = d.dependency_id
WHERE 
    car.severity >= 70
GROUP BY car.id, c.id, c.name, car.rustsec_id, car.severity, c.crate_downloads, c.repository
ORDER BY 
    car.severity DESC,
    total_exposure DESC;


-- Shows widely-used crates that have security vulnerabilities

SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(car.id) AS vuln_count,
    MAX(car.severity) AS max_severity,
    ROUND(AVG(car.severity)::numeric, 2) AS avg_severity,
    CASE 
        WHEN MAX(car.severity) >= 90 THEN 'CRITICAL'
        WHEN MAX(car.severity) >= 70 THEN 'HIGH'
        WHEN MAX(car.severity) >= 40 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity_rating,
    ARRAY_AGG('RUSTSEC-' || car.rustsec_id ORDER BY car.severity DESC) AS vulnerabilities,
    c.repository
FROM 
    crates c
    INNER JOIN cargo_audit_results car ON c.id = car.crate
WHERE 
    c.crate_downloads > 100000
GROUP BY 
    c.id, c.name, c.crate_downloads, c.repository
ORDER BY 
    c.crate_downloads DESC;


-- Shows crates and their full dependency tree vulnerability status

WITH RECURSIVE dep_tree AS (
    SELECT 
        c.id AS root_crate_id,
        c.name AS root_crate_name,
        c.id AS current_crate_id,
        c.name AS current_crate_name,
        0 AS depth,
        ARRAY[c.id] AS path
    FROM crates c
    
    UNION ALL
    
    SELECT 
        dt.root_crate_id,
        dt.root_crate_name,
        d.dependency_id,
        c.name,
        dt.depth + 1,
        dt.path || d.dependency_id
    FROM dep_tree dt
    JOIN dependencies d ON dt.current_crate_id = d.crate_id
    JOIN crates c ON d.dependency_id = c.id
    WHERE 
        dt.depth < 3  -- Limit to 3 levels deep
        AND NOT (d.dependency_id = ANY(dt.path))  -- Avoid cycles
)
SELECT 
    dt.root_crate_name AS crate_name,
    COUNT(DISTINCT dt.current_crate_id) AS total_deps_in_tree,
    COUNT(DISTINCT CASE WHEN car.id IS NOT NULL THEN dt.current_crate_id END) AS vulnerable_deps_in_tree,
    COUNT(DISTINCT car.id) AS total_vulnerabilities_in_tree,
    MAX(car.severity) AS max_severity_in_tree,
    STRING_AGG(DISTINCT 
        CASE WHEN car.id IS NOT NULL 
        THEN CONCAT(dt.current_crate_name, ' [depth:', dt.depth, ']')
        END, 
        ', '
    ) AS vulnerable_deps_list
FROM dep_tree dt
LEFT JOIN cargo_audit_results car ON dt.current_crate_id = car.crate
WHERE dt.root_crate_id IN (
    SELECT DISTINCT crate_id FROM dependencies LIMIT 100  -- Limit for performance
)
GROUP BY dt.root_crate_id, dt.root_crate_name
HAVING COUNT(DISTINCT CASE WHEN car.id IS NOT NULL THEN dt.current_crate_id END) > 0
ORDER BY total_vulnerabilities_in_tree DESC, max_severity_in_tree DESC
LIMIT 30;


-- Statistical overview of all vulnerabilities grouped by severity level

SELECT 
    CASE 
        WHEN severity >= 90 THEN 'CRITICAL'
        WHEN severity >= 70 THEN 'HIGH'
        WHEN severity >= 40 THEN 'MEDIUM'
        WHEN severity >= 10 THEN 'LOW'
        ELSE 'INFO'
    END AS severity_category,
    COUNT(*) AS vuln_count,
    COUNT(DISTINCT crate) AS affected_crates,
    ROUND(AVG(severity)::numeric, 2) AS avg_score_in_category,
    ROUND((COUNT(*)::numeric / SUM(COUNT(*)) OVER () * 100), 1) AS percentage_of_total
FROM 
    cargo_audit_results
GROUP BY 
    CASE 
        WHEN severity >= 90 THEN 'CRITICAL'
        WHEN severity >= 70 THEN 'HIGH'
        WHEN severity >= 40 THEN 'MEDIUM'
        WHEN severity >= 10 THEN 'LOW'
        ELSE 'INFO'
    END
ORDER BY 
    MIN(severity) DESC;


-- Statistics about the entire crate ecosystem security

SELECT 
    'Total Crates Analyzed' AS metric,
    COUNT(DISTINCT c.id)::text AS value
FROM crates c
INNER JOIN scan_results sr ON c.id = sr.id

UNION ALL

SELECT 
    'Crates with Direct Vulnerabilities' AS metric,
    COUNT(DISTINCT car.crate)::text AS value
FROM cargo_audit_results car

UNION ALL

SELECT 
    'Total Vulnerabilities Found' AS metric,
    COUNT(*)::text AS value
FROM cargo_audit_results

UNION ALL

SELECT 
    'Unique RustSec Advisories' AS metric,
    COUNT(DISTINCT rustsec_id)::text AS value
FROM cargo_audit_results

UNION ALL

SELECT 
    'Critical Vulnerabilities (>=9.0)' AS metric,
    COUNT(*)::text AS value
FROM cargo_audit_results
WHERE severity >= 90

UNION ALL

SELECT 
    'High Vulnerabilities' AS metric,
    COUNT(*)::text AS value
FROM cargo_audit_results
WHERE severity >= 70 AND severity < 90

UNION ALL

SELECT 
    'Average Severity Score' AS metric,
    ROUND(AVG(severity)::numeric, 2)::text AS value
FROM cargo_audit_results

UNION ALL

SELECT 
    'Most Common Vulnerability' AS metric,
    'RUSTSEC-' || rustsec_id AS value
FROM cargo_audit_results
GROUP BY rustsec_id
ORDER BY COUNT(*) DESC
LIMIT 1;


-- Shows crates that are themselves clean but depend on vulnerable packages

SELECT 
    c.name AS crate_name,
    c.crate_downloads,
    COUNT(DISTINCT vulnerable_dep.id) AS vulnerable_dependency_count,
    MAX(car.severity) AS max_inherited_severity,
    COUNT(DISTINCT car.id) AS total_inherited_vulnerabilities,
    STRING_AGG(DISTINCT 
        CONCAT(vulnerable_dep.name, ' (', COUNT(car.id), ' vulns)'),
        ', '
    ) AS vulnerable_dependencies
FROM crates c
INNER JOIN dependencies d ON c.id = d.crate_id
INNER JOIN crates vulnerable_dep ON d.dependency_id = vulnerable_dep.id
INNER JOIN cargo_audit_results car ON vulnerable_dep.id = car.crate
LEFT JOIN cargo_audit_results direct_car ON c.id = direct_car.crate
WHERE direct_car.id IS NULL  -- Crate itself has no vulnerabilities
GROUP BY c.id, c.name, c.crate_downloads
ORDER BY total_inherited_vulnerabilities DESC, max_inherited_severity DESC
LIMIT 50;

