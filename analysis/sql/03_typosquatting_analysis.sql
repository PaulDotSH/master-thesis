-- ============================================================================
-- TYPOSQUATTING ANALYSIS
-- ============================================================================ 
-- Analyzes name-similarity between crates to detect potential typosquatting.
-- Part A: Top suspicious pairs (high combined similarity score)
-- Part B: Distribution of similarity scores across the ecosystem
-- Part C: Pairs where one crate is popular and the other obscure (classic typosquat)
-- ============================================================================

-- PART A: Most suspicious typosquat pairs (combined_score >= 80)
SELECT 
    c1.name AS crate_name,
    c1.crate_downloads AS crate_downloads,
    c2.name AS similar_crate_name,
    c2.crate_downloads AS similar_crate_downloads,
    tr.combined_score,
    tr.levenshtein_score,
    tr.damerau_levenshtein_score,
    tr.jaro_winkler_score,
    tr.keyboard_distance_score,
    tr.prefix_similarity_score,
    CASE 
        WHEN c1.crate_downloads > c2.crate_downloads * 10 
             OR c2.crate_downloads > c1.crate_downloads * 10
        THEN 'YES'
        ELSE 'NO'
    END AS high_download_asymmetry
FROM typosquat_results tr
INNER JOIN crates c1 ON tr.crate_id = c1.id
INNER JOIN crates c2 ON tr.similar_crate_id = c2.id
WHERE tr.combined_score >= 80
ORDER BY tr.combined_score DESC, high_download_asymmetry DESC
LIMIT 50;

-- PART B: Combined score distribution (for histogram)
SELECT 
    WIDTH_BUCKET(combined_score, 0, 100, 20) AS score_bucket,
    (WIDTH_BUCKET(combined_score, 0, 100, 20) - 1) * 5 AS bucket_lower_bound,
    COUNT(*) AS pair_count
FROM typosquat_results
GROUP BY score_bucket
ORDER BY score_bucket;

-- PART C: High-asymmetry typosquat pairs (classic attack pattern)
-- One crate is popular (>10k downloads), the similar one is obscure (<1k downloads)
SELECT 
    c1.name AS popular_crate,
    c1.crate_downloads AS popular_downloads,
    c2.name AS obscure_crate,
    c2.crate_downloads AS obscure_downloads,
    tr.combined_score,
    ROUND(c1.crate_downloads::numeric / GREATEST(c2.crate_downloads, 1), 0) AS download_ratio
FROM typosquat_results tr
INNER JOIN crates c1 ON tr.crate_id = c1.id
INNER JOIN crates c2 ON tr.similar_crate_id = c2.id
WHERE c1.crate_downloads > 10000 
  AND c2.crate_downloads < 1000
  AND tr.combined_score >= 60
ORDER BY tr.combined_score DESC, download_ratio DESC
LIMIT 30;

-- Summary stats for text output
SELECT 
    COUNT(*) AS total_typosquat_pairs,
    ROUND(AVG(combined_score)::numeric, 2) AS avg_combined_score,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY combined_score) AS median_score,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY combined_score) AS p95_score,
    MAX(combined_score) AS max_score,
    COUNT(*) FILTER (WHERE combined_score >= 80) AS high_similarity_pairs,
    COUNT(*) FILTER (WHERE combined_score >= 90) AS very_high_similarity_pairs
FROM typosquat_results;
