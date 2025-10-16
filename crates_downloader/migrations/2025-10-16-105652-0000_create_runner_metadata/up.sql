CREATE TABLE runner_metadata(
    run_time TIMESTAMP PRIMARY KEY NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_checked_crate BIGINT references crates(id) DEFAULT NULL
);