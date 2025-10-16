CREATE TABLE dependencies (
    crate_id BIGINT NOT NULL references crates(id),
    dependency_id BIGINT NOT NULL references crates(id),
    db_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create primary key on both columns
ALTER TABLE dependencies ADD CONSTRAINT pk_dependencies PRIMARY KEY (crate_id, dependency_id);
CREATE INDEX idx_dependencies_created_at ON dependencies (db_created_at);
CREATE INDEX idx_dependencies_updated_at ON dependencies (db_updated_at);