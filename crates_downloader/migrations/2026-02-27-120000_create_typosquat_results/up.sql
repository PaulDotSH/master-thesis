CREATE TABLE typosquat_results (
    id BIGSERIAL PRIMARY KEY,
    crate_id BIGINT NOT NULL REFERENCES crates(id),
    similar_crate_id BIGINT NOT NULL REFERENCES crates(id),
    levenshtein_score SMALLINT NOT NULL,
    damerau_levenshtein_score SMALLINT NOT NULL,
    jaro_winkler_score SMALLINT NOT NULL,
    keyboard_distance_score SMALLINT NOT NULL,
    prefix_similarity_score SMALLINT NOT NULL,
    combined_score SMALLINT NOT NULL,
    db_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(crate_id, similar_crate_id),
    
    -- Prevent self-comparison
    CHECK(crate_id != similar_crate_id)
);

CREATE INDEX idx_typosquat_crate_id ON typosquat_results(crate_id);
CREATE INDEX idx_typosquat_similar_crate_id ON typosquat_results(similar_crate_id);
CREATE INDEX idx_typosquat_combined_score ON typosquat_results(combined_score DESC);
