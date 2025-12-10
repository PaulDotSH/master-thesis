CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE gitleaks_results ( 
    id uuid PRIMARY KEY default uuid_generate_v4(),
    crate BIGINT references crates(id),
    rule_id varchar(255) not null,
    secret varchar(255) not null,
    loc varchar(255) not null,
    entropy double precision not null
);

CREATE INDEX idx_gitleaks_results ON gitleaks_results(crate);