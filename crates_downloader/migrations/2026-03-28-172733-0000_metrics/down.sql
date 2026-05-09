-- Drop the analysis_metrics table and its indexes
DROP INDEX IF EXISTS idx_analysis_metrics_worker_id;
DROP INDEX IF EXISTS idx_analysis_metrics_completed_at;
DROP INDEX IF EXISTS idx_analysis_metrics_crate_id;
DROP TABLE IF EXISTS analysis_metrics;
