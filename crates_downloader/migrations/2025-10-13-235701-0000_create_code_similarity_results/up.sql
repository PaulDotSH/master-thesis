CREATE TABLE code_similarity_results (
    crate_id BIGINT references crates(id),
    other_crate_id BIGINT references crates(id),
    code_similarity_score SMALLINT NOT NULL
);

-- Create primary key on both columns
ALTER TABLE code_similarity_results ADD CONSTRAINT pk_code_similarity_results PRIMARY KEY (crate_id, other_crate_id);