CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE gitleaks_results ( 
    id uuid PRIMARY KEY default uuid_generate_v4(),
    crate BIGINT references crates(id),
    rustsec_id varchar(10) not null,
    severity smallint default null
);

CREATE INDEX idx_gitleaks_results ON gitleaks_results(crate);
