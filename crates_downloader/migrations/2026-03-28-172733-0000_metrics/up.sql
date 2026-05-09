-- Create analysis_metrics table to track execution time for each crate analysis
CREATE TABLE analysis_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crate_id BIGINT NOT NULL REFERENCES crates(id) ON DELETE CASCADE,

    -- Overall timing
    total_duration_ms BIGINT NOT NULL,

    -- Individual analysis step durations (in milliseconds)
    cargo_audit_duration_ms BIGINT,
    gitleaks_duration_ms BIGINT,
    executable_check_duration_ms BIGINT,
    build_rs_analysis_duration_ms BIGINT,
    llm_analysis_duration_ms BIGINT,

    -- Download timing
    download_duration_ms BIGINT,

    -- Worker information
    worker_id VARCHAR(255),

    -- Timestamps
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for querying by crate
CREATE INDEX idx_analysis_metrics_crate_id ON analysis_metrics(crate_id);

-- Index for querying by completion time
CREATE INDEX idx_analysis_metrics_completed_at ON analysis_metrics(completed_at);

-- Index for querying by worker
CREATE INDEX idx_analysis_metrics_worker_id ON analysis_metrics(worker_id);
