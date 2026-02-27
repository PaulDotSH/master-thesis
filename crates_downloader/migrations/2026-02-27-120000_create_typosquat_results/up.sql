CREATE TABLE typosquat_results (
    id BIGSERIAL PRIMARY KEY,
    crate_id BIGINT NOT NULL REFERENCES crates(id),
    similar_crate_id BIGINT NOT NULL REFERENCES crates(id),
    
    -- Individual algorithm scores (0-100 scale, higher = more similar)
    levenshtein_score SMALLINT NOT NULL,
    damerau_levenshtein_score SMALLINT NOT NULL,
    jaro_winkler_score SMALLINT NOT NULL,
    keyboard_distance_score SMALLINT NOT NULL,
    prefix_similarity_score SMALLINT NOT NULL,
    
    -- Combined weighted score (0-100)
    combined_score SMALLINT NOT NULL,
    
    -- Metadata
    db_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Ensure we don't have duplicate pairs
    UNIQUE(crate_id, similar_crate_id),
    
    -- Prevent self-comparison
    CHECK(crate_id != similar_crate_id)
);

-- Index for looking up similar crates for a given crate
CREATE INDEX idx_typosquat_crate_id ON typosquat_results(crate_id);

-- Index for finding crates that are similar to a given crate (reverse lookup)
CREATE INDEX idx_typosquat_similar_crate_id ON typosquat_results(similar_crate_id);

-- Index for filtering by combined score (to find high-risk typosquats)
CREATE INDEX idx_typosquat_combined_score ON typosquat_results(combined_score DESC);
