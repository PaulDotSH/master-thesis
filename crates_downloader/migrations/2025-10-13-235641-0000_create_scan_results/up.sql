CREATE TABLE scan_results ( 
    id BIGINT PRIMARY KEY references crates(id),
    has_malicious_dependencies BOOLEAN NOT NULL,
    llm_malicious_score SMALLINT NOT NULL,
    llm_notes VARCHAR NOT NULL,
    has_executable_files BOOLEAN not null,
    cargo_audit_max_dep_score smallint not null,
    cargo_audit_vulns_count smallint not null
)