-- Create analysis_metrics table to track execution time for each crate analysis
CREATE TABLE analysis_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crate_id BIGINT NOT NULL REFERENCES crates(id) ON DELETE CASCADE,
    total_duration_ms BIGINT NOT NULL,
    cargo_audit_duration_ms BIGINT,
    gitleaks_duration_ms BIGINT,
    executable_check_duration_ms BIGINT,
    build_rs_analysis_duration_ms BIGINT,
    llm_analysis_duration_ms BIGINT,
    download_duration_ms BIGINT,
    worker_id VARCHAR(255),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_analysis_metrics_crate_id ON analysis_metrics(crate_id);
CREATE INDEX idx_analysis_metrics_completed_at ON analysis_metrics(completed_at);
CREATE INDEX idx_analysis_metrics_worker_id ON analysis_metrics(worker_id);
