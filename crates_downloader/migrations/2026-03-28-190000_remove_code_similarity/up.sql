-- Remove code-similarity style aggregate entropy metric from scan results
ALTER TABLE scan_results
    DROP COLUMN IF EXISTS entropy_score;
