// @generated automatically by Diesel CLI.

diesel::table! {
    cargo_audit_results (id) {
        id -> Uuid,
        #[sql_name = "crate"]
        crate_ -> Nullable<Int8>,
        #[max_length = 10]
        rustsec_id -> Varchar,
        severity -> Nullable<Int2>,
    }
}

diesel::table! {
    code_similarity_results (crate_id, other_crate_id) {
        crate_id -> Int8,
        other_crate_id -> Int8,
        code_similarity_score -> Int2,
    }
}

diesel::table! {
    crates (id) {
        id -> Int8,
        name -> Text,
        repository -> Text,
        crate_downloads -> Int8,
        db_created_at -> Timestamp,
        db_updated_at -> Timestamp,
        crate_created_at -> Timestamp,
        crate_updated_at -> Timestamp,
    }
}

diesel::table! {
    dependencies (crate_id, dependency_id) {
        crate_id -> Int8,
        dependency_id -> Int8,
        db_created_at -> Timestamp,
        db_updated_at -> Timestamp,
    }
}

diesel::table! {
    gitleaks_results (id) {
        id -> Uuid,
        #[sql_name = "crate"]
        crate_ -> Nullable<Int8>,
        #[max_length = 255]
        rule_id -> Varchar,
        #[max_length = 255]
        secret -> Varchar,
        #[max_length = 255]
        loc -> Varchar,
        entropy -> Float8,
    }
}

diesel::table! {
    runner_metadata (run_time) {
        run_time -> Timestamp,
        last_checked_crate -> Nullable<Int8>,
    }
}

diesel::table! {
    scan_results (id) {
        id -> Int8,
        has_malicious_dependencies -> Bool,
        llm_malicious_score -> Int2,
        llm_notes -> Varchar,
        has_executable_files -> Bool,
        cargo_audit_max_dep_score -> Int2,
        cargo_audit_vulns_count -> Int2,
        db_created_at -> Timestamp,
    }
}

diesel::joinable!(cargo_audit_results -> crates (crate_));
diesel::joinable!(gitleaks_results -> crates (crate_));
diesel::joinable!(runner_metadata -> crates (last_checked_crate));
diesel::joinable!(scan_results -> crates (id));

diesel::allow_tables_to_appear_in_same_query!(
    cargo_audit_results,
    code_similarity_results,
    crates,
    dependencies,
    gitleaks_results,
    runner_metadata,
    scan_results,
);
