-- PostgreSQL schema
CREATE TABLE crates (
    id BIGINT PRIMARY KEY,
    name Text NOT NULL,
    repository TEXT NOT NULL,
    crate_downloads BIGINT NOT NULL,
    db_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    crate_created_at TIMESTAMP NOT NULL,
    crate_updated_at TIMESTAMP NOT NULL,
);

CREATE INDEX idx_crates_c_updated_at ON crates (crate_updated_at);
CREATE INDEX idx_crates_c_created_at ON crates (crate_created_at);
CREATE INDEX idx_crates_db_updated_at ON crates (db_updated_at);
CREATE INDEX idx_crates_db_created_at ON crates (db_created_at);


CREATE TABLE dependencies (
    crate_id BIGINT NOT NULL references crates(id),
    dependency_id BIGINT NOT NULL references crates(id),
    db_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
);

CREATE UNIQUE INDEX idx_dependencies ON dependencies (crate_id, dependency_id);
CREATE INDEX idx_dependencies_created_at ON dependencies (db_created_at);
CREATE INDEX idx_dependencies_updated_at ON dependencies (db_updated_at);

CREATE TABLE scan_results ( 
    id BIGINT PRIMARY KEY references crates(id),
    has_malicious_dependencies BOOLEAN NOT NULL,
    llm_malicious_score SMALLINT NOT NULL,
)