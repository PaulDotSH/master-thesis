# Master Thesis — Crate Security Analysis Platform

## 1. Overview

This project is a distributed, high-performance security analysis platform for the Rust crate ecosystem. It downloads the crates.io database dump, builds a local PostgreSQL database of crates and their dependencies, then performs multi-faceted security analysis on each crate using a horizontally-scalable worker architecture.

**Key capabilities:**

- Downloads and parses crates.io CSV exports (crates, dependencies, versions, downloads)
- Clones crate repositories from GitHub/GitLab/etc.
- Runs 5 analysis tools per crate: `cargo-audit` (vulnerabilities), `gitleaks` (secrets), binary detection, `build.rs` analysis, and LLM-based code review
- Detects typosquatting via 5 string-similarity algorithms
- Distributes work across 1–50+ worker containers using a Redis-based dependency-aware work queue
- Provides a web dashboard (Axum + PostgreSQL) for exploring results

---

## 2. Architecture Overview

```
┌────────────────────┐
│  crates.io CDN     │  static.crates.io
│  (db-dump.tar.gz)  │
└────────┬───────────┘
         │ download
         ▼
┌────────────────────┐
│   crates_downloader│  CLI (Rust)
│   ┌──────────────┐ │
│   │ update-db    │ │  Downloads CSV → PostgreSQL
│   │ run-analysis │ │  Builds dependency graph → Redis
│   │ worker       │ │  Consumes queue → analyzes crates
│   │ typosquat    │ │  Pairwise name comparison
│   └──────────────┘ │
└──┬──────────┬──────┘
   │          │
   ▼          ▼
┌───────┐ ┌───────┐
│Redis  │ │PostgreSQL│
│Queue  │ │ 17     │
│Deps   │ │        │
│Graph  │ │        │
└───────┘ └───┬────┘
              │
              ▼
┌────────────────────┐
│   webpanel         │  Axum web server
│   ┌──────────────┐ │
│   │ REST API     │ │  /api/stats, /api/crates, ...
│   │ Static files │ │  HTML/CSS/JS dashboard
│   └──────────────┘ │
└────────────────────┘
```

### Data Flow

1. **Data Import**: `crates_downloader update-database` downloads `db-dump.tar.gz` from `static.crates.io`, extracts CSV files (`crates.csv`, `dependencies.csv`, `crate_downloads.csv`, `versions.csv`), and populates or incrementally updates the PostgreSQL database.

2. **Queue Initialization**: `crates_downloader run-analysis` reads all crate IDs and their dependencies from PostgreSQL, builds a dependency graph in Redis, and populates a ready-queue for workers. It detects and breaks dependency cycles upfront using DFS.

3. **Distributed Analysis**: Workers (Docker containers or local processes) consume crate IDs from the Redis ready queue. Each crate is analyzed sequentially: `git clone` → parallel analysis (cargo-audit, gitleaks, executable check, build.rs, LLM) → results insertion → dependency promotion.

4. **Web Dashboard**: The `webpanel` Axum server reads from PostgreSQL and serves a dark-themed dashboard with paginated tables, charts, and filtering.

5. **Post-Processing**: `compute-dependencies` marks crates whose transitive dependencies contain vulnerabilities or high LLM scores.

---

## 3. Directory Structure

```
master-thesis/
├── Cargo.toml                       # Workspace root (crates_downloader + webpanel)
├── Cargo.lock                       # Pinned dependencies
├── config.toml                      # Default application config
├── Dockerfile                       # Multi-stage Docker build
├── docker-compose.yml               # Full stack (postgres + redis + worker)
├── docker-compose.workers.yml       # Worker-only stack (host networking)
├── .dockerignore                    # Docker build exclusions
├── entrypoint.sh                    # Docker entrypoint (mounts cargo home)
│
├── crates_downloader/               # Main CLI crate
│   ├── Cargo.toml                   # Dependencies (diesel, tokio, redis, clap, ...)
│   ├── config.toml                  # Worker-specific config
│   ├── diesel.toml                  # Diesel CLI config (schema, migrations dir)
│   ├── .env                         # Local DATABASE_URL
│   ├── SCALING.md                   # Distributed architecture overview
│   ├── architecture.md              # Early project description
│   ├── schema.sql                   # Initial schema proposal
│   ├── src/
│   │   ├── main.rs                  # CLI entry point (clap subcommands)
│   │   ├── config.rs                # Config struct (TOML + env overrides)
│   │   ├── database.rs              # bb8 connection pool
│   │   ├── models.rs                # Diesel models & CSV structs
│   │   ├── schema.rs                # Diesel-generated schema
│   │   ├── queue.rs                 # Redis dependency-graph work queue
│   │   ├── downloader.rs            # crates.io archive downloader
│   │   ├── csv_reader.rs            # CSV parsing
│   │   ├── data_import.rs           # DB population & incremental update
│   │   ├── analysis/
│   │   │   ├── mod.rs
│   │   │   ├── analysis.rs          # Core orchestration (895 lines)
│   │   │   ├── audit.rs             # cargo-audit runner + CVSS parser
│   │   │   ├── gitleaks.rs          # gitleaks runner
│   │   │   ├── llm.rs               # LM Studio API integration
│   │   │   ├── typosquat.rs         # 5 similarity algorithms
│   │   │   └── build_rs.rs          # build.rs suspicious pattern analysis
│   │   └── repositories/
│   │       ├── mod.rs
│   │       ├── crates.rs            # Crate CRUD
│   │       ├── dependencies.rs      # Dependency graph ops
│   │       ├── download.rs          # Git clone with error classification
│   │       ├── scan_results.rs      # Needs-analysis batch check
│   │       └── typosquat.rs         # Typosquat results CRUD
│   ├── migrations/                  # Diesel SQL migrations (11 total)
│   │   ├── 00000000000000_diesel_initial_setup/
│   │   ├── 2025-10-13-235504_create_crates/
│   │   ├── 2025-10-13-235618_create_depdendencies/
│   │   ├── 2025-10-13-235641_create_scan_results/
│   │   ├── 2025-10-16-105652_create_runner_metadata/
│   │   ├── 2025-10-16-111901_create_cargo_audit_results/
│   │   ├── 2025-10-16-112318_create_gitleaks_results/
│   │   ├── 2026-02-27-120000_create_typosquat_results/
│   │   ├── 2026-02-27-130000_add_build_rs_analysis/
│   │   ├── 2026-03-28-172733-0000_metrics/
│   │   └── 2026-03-28-190000_remove_code_similarity/
│   └── logs/
│
├── webpanel/                        # Web dashboard crate
│   ├── Cargo.toml                   # Dependencies (axum, tower-http, diesel-async, ...)
│   ├── config.toml                  # Server config (host, port, DB)
│   ├── src/
│   │   ├── main.rs                  # Axum server setup, routes, CORS, static files
│   │   ├── config.rs                # Server config struct
│   │   ├── db.rs                    # bb8 pool creation
│   │   ├── models.rs                # Queryable + dashboard stats structs
│   │   ├── schema.rs                # Diesel schema (mirrors crates_downloader)
│   │   └── routes/
│   │       ├── mod.rs               # Pagination, AppError
│   │       ├── dashboard.rs         # Aggregate stats API
│   │       ├── crates.rs            # Crate listing/detail
│   │       ├── dependencies.rs      # Dependency listing
│   │       ├── scan_results.rs      # Scan results + search
│   │       ├── cargo_audit.rs       # Vulnerability listing
│   │       ├── gitleaks.rs          # Secrets listing
│   │       ├── typosquat.rs         # Typosquat pairs
│   │       └── metrics.rs           # Timing metrics API
│   └── static/                      # Frontend (HTML, CSS, JS)
│       ├── index.html               # Dashboard page
│       ├── crates.html
│       ├── dependencies.html
│       ├── scan-results.html
│       ├── vulnerabilities.html
│       ├── secrets.html
│       ├── typosquat.html
│       ├── metrics.html
│       ├── css/style.css            # Dark theme (572 lines)
│       └── js/
│           ├── api.js               # API client + DataTable component
│           └── dashboard.js         # Chart.js visualizations
│
├── analysis/                        # Dissertation analysis scripts
│   ├── run.sh                       # Orchestrator for SQL + Python
│   ├── analyze.py                   # 15 matplotlib visualizations
│   └── sql/                         # 10+ analysis SQL queries
│       ├── 01_most_vulnerable_crates.sql
│       ├── 02_vuln_per_download_ratio.sql
│       ├── 03_typosquatting_analysis.sql
│       ├── 04_secrets_leaked.sql
│       ├── 05_build_rs_suspicious.sql
│       ├── 06_llm_score_correlation.sql
│       ├── 07_executable_files_analysis.sql
│       ├── 08_dependency_network.sql
│       ├── 09_temporal_analysis.sql
│       ├── 10_ecosystem_overview.sql
│       ├── crates_with_most_vulnerabilities.sql
│       └── quick_reference.sql
│
├── logs/                            # Runtime logs
├── db-dump/                         # Downloaded CSV files (gitignored)
│
├── latex-template/                  # Master's thesis LaTeX source
│   ├── main_file_template_bachelor_masters_english.tex
│   ├── cap1.tex – cap9.tex          # 9 chapters
│   ├── appendixA.tex – appendixE.tex # 5 appendices
│   ├── mybib.bib                    # Bibliography
│   ├── thesis_draft.md              # Draft
│   └── poster/                      # Conference poster
│
├── build-docker.sh                  # docker build wrapper
├── composer-down.sh                 # docker-compose down
├── docker-cleanup.sh                # Prune containers/images
├── docker-logs.sh                   # Filter logs for errors
├── mout-ramdisk.sh                  # Mount /tmp/crates as tmpfs
├── reset-all.sh                     # Full reset pipeline
├── reset-database.sh                # Drop/create DB + migrations
├── start-timed.sh                   # Workers with timeout
├── start-workers.sh                 # Start N workers
└── tmpfix.sh                        # (empty placeholder)
```

---

## 4. Database Schema

### Migration History

| Migration | Table | Purpose |
|-----------|-------|---------|
| `00000000000000` | — | Diesel utility functions (`diesel_manage_updated_at`) |
| `2025-10-13-235504` | `crates` | Core crate metadata (id, name, repository, downloads, timestamps) |
| `2025-10-13-235618` | `dependencies` | Crate→dependency edges with compound PK |
| `2025-10-13-235641` | `scan_results` | Per-crate analysis results (1:1 with crates) |
| `2025-10-16-105652` | `runner_metadata` | Analysis run checkpoints (last_checked_crate) |
| `2025-10-16-111901` | `cargo_audit_results` | Vulnerability findings (RUSTSEC IDs, CVSS severity) |
| `2025-10-16-112318` | `gitleaks_results` | Secret leak findings (rule ID, secret, location, entropy) |
| `2026-02-27-120000` | `typosquat_results` | Name similarity pairs with 6 score dimensions |
| `2026-02-27-130000` | `scan_results` (ALTER) | 6 build.rs analysis columns + checkpoint |
| `2026-03-28-172733` | `analysis_metrics` | Per-crate timing data (download, audit, gitleaks, LLM, etc.) |
| `2026-03-28-190000` | `scan_results` (ALTER) | Removes `entropy_score` (replaced by build.rs-specific entropy) |

### Key Table: `crates`

```sql
CREATE TABLE crates (
    id BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    repository TEXT NOT NULL,
    crate_downloads BIGINT NOT NULL,
    db_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    crate_created_at TIMESTAMP NOT NULL,
    crate_updated_at TIMESTAMP NOT NULL
);
```

### Key Table: `scan_results`

```sql
CREATE TABLE scan_results (
    id BIGINT PRIMARY KEY REFERENCES crates(id),
    has_malicious_dependencies BOOLEAN NOT NULL,
    llm_malicious_score SMALLINT NOT NULL,
    llm_notes VARCHAR NOT NULL,
    has_executable_files BOOLEAN NOT NULL,
    cargo_audit_max_dep_score SMALLINT NOT NULL,
    cargo_audit_vulns_count SMALLINT NOT NULL,
    -- Build.rs analysis:
    build_rs_network_calls BOOLEAN,
    build_rs_has_link_directive BOOLEAN,
    build_rs_entropy_score REAL,
    build_rs_has_process_spawning BOOLEAN,
    build_rs_has_raw_ip BOOLEAN,
    build_rs_has_free_tlds BOOLEAN,
    db_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Key Table: `analysis_metrics`

```sql
CREATE TABLE analysis_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crate_id BIGINT NOT NULL REFERENCES crates(id) ON DELETE CASCADE,
    total_duration_ms BIGINT NOT NULL,
    cargo_audit_duration_ms BIGINT,
    gitleaks_duration_ms BIGINT,
    executable_check_duration_ms BIGINT,
    build_rs_analysis_duration_ms BIGINT,
    llm_analysis_duration_ms BIGINT,
    download_duration_ms BIGINT,
    worker_id VARCHAR(255),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Key Table: `typosquat_results`

```sql
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
    CHECK(crate_id != similar_crate_id)
);
```

---

## 5. CLI Tool: `crates_downloader`

The application is a single binary with subcommands defined via `clap`. It supports 13 subcommands:

| Subcommand | Description |
|-----------|-------------|
| `update-database` | Downloads crates.io data dump, populates/updates PostgreSQL |
| `run-analysis` | Builds dependency graph in Redis, queues crates for workers |
| `worker` | Redis queue consumer loop with graceful shutdown |
| `compute-dependencies` | Updates `has_malicious_dependencies` column via SQL |
| `queue-status` | Prints Redis queue statistics (ready/in-progress/completed/failed) |
| `recover-stale` | Moves items stuck in `in_progress` back to ready queue |
| `clear-queue` | Destroys all Redis `crate:*` keys (requires confirmation) |
| `fix-cycles` | Removes self-references and stale completed deps |
| `break-cycles` | DFS-based detection and edge removal for complex cycles |
| `scan-crate --name <name>` | Sequential, single-process scan of a crate + its dependencies |
| `queue-crate --name <name>` | Queues a single crate's dependency tree for distributed workers |
| `check-llm` | Verifies LM Studio API connectivity |
| `typosquat` | Pairwise name comparison across all crates using rayon |

### Logging

The application uses `tracing_subscriber` with dual output:
- **Console**: formatted logs at the configured `RUST_LOG` level
- **File**: daily rolling log files in `logs/crates_downloader.log.YYYY-MM-DD`

---

## 6. Analysis Pipeline (Per-Crate)

For each crate, the worker performs the following steps:

```
┌──────────────┐
│ 1. Git clone │  --depth 1 --single-branch --filter=blob:none
└──────┬───────┘
       ▼
┌──────────────────────────────────────────────────────────┐
│              2. Parallel Analysis (tokio::join!)         │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌─────┐│
│  │cargo-audit│ │gitleaks  │ │Exec     │ │build.rs│ │LLM  ││
│  │(--no-fetch│ │(dir scan)│ │Check    │ │Analysis│ │     ││
│  │ --db      │ │          │ │         │ │        │ │     ││
│  │ /advisory-│ │          │ │         │ │        │ │     ││
│  │ db)       │ │          │ │         │ │        │ │     ││
│  └──────────┘ └──────────┘ └─────────┘ └────────┘ └─────┘│
└───────────────────────┬──────────────────────────────────┘
                        ▼
┌──────────────────────────────────────────┐
│ 3. Results aggregation + DB insertion    │
│    - scan_results (ON CONFLICT upsert)   │
│    - cargo_audit_results                 │
│    - gitleaks_results                    │
│    - analysis_metrics (timing)           │
└──────────────┬───────────────────────────┘
               ▼
┌──────────────────────┐
│ 4. Crate marked       │
│    completed in Redis │
│    → Dependents       │
│      promoted to      │
│      ready queue      │
└──────────────┬────────┘
               ▼
┌──────────────────────┐
│ 5. Cleanup            │
│    - Delete temp dir  │
│    - Every 100 crates:│
│      clean cargo      │
│      target/          │
└──────────────────────┘
```

### Analysis Module Details

#### 5a. `cargo-audit` (`audit.rs`)

Runs `cargo-audit audit --json --no-fetch --db /advisory-db` against the cloned crate directory. Parses the JSON output to extract:
- **RUSTSEC ID**: Advisory identifier (with `RUSTSEC-` prefix stripped)
- **Severity**: Computed from the CVSS 3.1 vector string using a custom implementation that evaluates attack vector (AV), attack complexity (AC), privileges required (PR), user interaction (UI), scope (S), confidentiality (C), integrity (I), and availability (A) impact metrics. The CVSS base score is scaled 0–100 and stored as a `SMALLINT`.

Exit code 0 = no vulnerabilities; code 1 = vulnerabilities found (both are valid).

#### 5b. `gitleaks` (`gitleaks.rs`)

Runs `gitleaks -f json -r tmp.json dir` in the crate directory. Parses the JSON output array extracting:
- `RuleID` — the type of secret detected (e.g., `aws-access-key`, `generic-api-key`)
- `Secret` — the detected secret string
- `Fingerprint` — file location (used as the `loc` field in DB)
- `Entropy` — Shannon entropy of the detected secret

Exit code 1 means leaks were found (valid); other non-zero codes are errors.

#### 5c. Executable File Detection (`analysis.rs`)

Uses the `find` command to locate files with execute bits set (`-perm /111`), `.exe`, `.dll`, `.so`, `.dylib` extensions. For each found file, reads the first 8 bytes to detect binary signatures:
- **ELF**: `0x7F 0x45 0x4C 0x46`
- **Mach-O**: `0xCAFEBABE`, `0xFEEDFACE`, `0xFEEDFACF`, `0xCFFAEDFE`, `0xCEFAEDFE`
- **PE (Windows)**: `0x4D 0x5A` (MZ header)
- **WebAssembly**: `0x00 0x61 0x73 0x6D` (`\0asm`)
- **Shebang scripts**: `0x23 0x21` (#!) — noted but not flagged as binary

#### 5d. `build.rs` Analysis (`build_rs.rs`)

Analyzes `build.rs` content for 6 suspicious indicators:

| Check | Method | Flags |
|-------|--------|-------|
| Network calls | String matching against 19 library keywords (reqwest, hyper, curl, TcpStream, etc.) | `build_rs_network_calls` |
| Link directives | Regex: `#\[link\]`, `cargo:rustc-link-lib`, `cargo:rustc-link-search` | `build_rs_has_link_directive` |
| Entropy | Shannon entropy of byte distribution (0.0–8.0) | `build_rs_entropy_score` |
| Process spawning | Regex: `Command::new`, `process::Command`, `.exec(`, `.spawn(` | `build_rs_has_process_spawning` |
| Raw IP addresses | Regex for IPv4, excludes local/private ranges (127.x, 10.x, 172.16-31.x, 192.168.x, 0.x, 169.254.x) | `build_rs_has_raw_ip` |
| Free TLDs | Regex for `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.work`, `.click`, `.link`, `.host` | `build_rs_has_free_tlds` |

Includes 50+ unit tests covering entropy calculation, IP validation, network call detection, and TLD matching.

#### 5e. LLM Analysis (`llm.rs`)

Optional LLM-based malicious code detection via LM Studio's OpenAI-compatible API:

1. **File collection**: Walks the crate directory, collects source files (`.rs`, `.py`, `.js`, `.sh`, `.c`, `.go`, etc.), skips hidden dirs, `target/`, `node_modules`, files > 256KB
2. **Batching**: Prioritizes `build.rs`, `lib.rs`, `main.rs`, `mod.rs`. Splits files into batches fitting within `llm_max_context_chars` (default 24KB)
3. **API call**: Sends system prompt + batched source to `POST /v1/chat/completions` with configurable model, max_tokens, and temperature
4. **Response parsing**: Extracts `SCORE: <0-100>` and `SUMMARY:` from the LLM response
5. **Aggregation**: Maximum score across all batches for the crate

The system prompt instructs the LLM to detect: remote code execution, reverse shells, data exfiltration, obfuscation, credential theft, crypto mining, and supply chain attack patterns.

---

## 7. Typosquatting Detection (`typosquat.rs`)

Detects potential typosquatting pairs among crate names using 5 string-similarity algorithms:

| Algorithm | Weight | Description |
|-----------|--------|-------------|
| Levenshtein distance | 20% | Minimum single-character edits (insertions, deletions, substitutions) |
| Damerau-Levenshtein distance | 25% | Levenshtein + adjacent character transpositions |
| Jaro-Winkler similarity | 25% | Character matching with prefix bonus (up to 4 chars, 0.1 scaling) |
| Keyboard distance | 15% | QWERTY layout coordinate-based distance between different characters |
| Prefix similarity | 15% | Common prefix ratio with bonus for prefixes ≥ 3 characters |

**Combined score** = weighted average of the 5 individual scores (0–100).

**Optimizations:**
- Length-difference heuristic: skips pairs where the length difference exceeds 30% of the longer name
- Self-comparison skip
- Target symmetry skip: if both crates are in the target set, only compare if the first has fewer downloads
- Parallel processing via `rayon` (flat_map over all crates × targets)
- Results inserted in batches of 1000 via `ON CONFLICT DO NOTHING`

Includes unit tests for all 5 algorithms.

---

## 8. Distributed Architecture (Redis Queue)

### Redis Data Structures

```
crate:ready            LIST       Crate IDs ready for processing (no pending deps)
crate:in_progress      SET        Crate IDs currently claimed by workers
crate:completed        SET        Successfully processed crate IDs
crate:failed           SET        Failed crate IDs (won't block dependents)
crate:total            STRING     Total count of crates in the queue
crate:deps:<id>        SET        Unprocessed dependency IDs for each crate
crate:dependents:<id>  SET        Reverse index: crates that depend on this crate
```

### Queue Operations

**`initialize_dependency_graph(crate_ids, dependencies)`**
1. Clears all existing `crate:*` keys
2. Sets `crate:total`
3. Builds filtered graph (only crates in the processing set, removes self-references)
4. Detects cycles via DFS coloring (white/gray/black) and breaks them upfront
5. Stores deps and reverse deps in Redis in batches of 1000 using Redis pipelines
6. Crates with zero dependencies go directly to `crate:ready`

**`pop_ready_crate_blocking(timeout_secs)`**
1. First attempts non-blocking `LPOP` + `SADD` to `in_progress` (Lua-script atomic)
2. Falls back to `BLPOP` with timeout
3. On receive, checks if already completed → skip and retry
4. Atomically attempts `SADD` to `in_progress` — if another worker claimed it first (SADD returns 0), retries
5. This dual mechanism prevents race conditions at scale

**`mark_completed(crate_id)`** (Atomic Lua script)
1. `SREM` from `in_progress`, `SADD` to `completed`
2. Reads `crate:dependents:<crate_id>` — all crates that depend on this one
3. For each dependent: `SREM` this crate from `crate:deps:<dependent_id>`
4. If a dependent now has zero remaining deps (`SCARD` = 0): `RPUSH` to `crate:ready`
5. Cleans up the dependents key

**`mark_failed(crate_id)`**
Adds to `crate:failed` set, then calls `mark_completed` (dependents still unblock).

**`fix_dependency_cycles()`**
Two-phase approach:
- Phase 1: Removes self-references and dependencies on already-completed crates
- Phase 2 (`break_complex_cycles`): Builds in-memory graph of pending-to-pending dependencies, runs DFS with coloring to find cycle edges, removes one edge per cycle

### Graceful Shutdown

Workers handle `SIGTERM`/`SIGINT` (Ctrl+C) gracefully:
1. Sets an `AtomicBool` shutdown flag
2. Main loop checks the flag before each iteration
3. If a crate is in progress, it is requeued via `requeue_item` (moved back to the front of the ready queue)
4. Logs shutdown complete and exits

### Container Lifecycle Management

Workers exit after `MAX_CRATES_PER_CONTAINER` (1000) crates to allow Docker to recreate the container with a fresh overlay2 filesystem. This prevents unbounded disk growth from accumulated toolchain files. Combined with `restart: always` in compose, workers are continuously recycled.

### Queue Statistics

```rust
struct QueueStats {
    ready: usize,
    in_progress: usize,
    completed: usize,
    failed: usize,
    total: usize,
}
```

Display format: `Progress: 42.5% | Ready: 500 | In Progress: 24 | Completed: 4250 | Failed: 12 | Remaining: 5738 / 10000`

---

## 9. Docker Deployment

### Dockerfile Architecture

The Dockerfile uses a multi-stage build pattern:

**Stage 1: Builder** (`rustlang/rust:nightly-slim`)
1. Installs build deps: `pkg-config`, `libssl-dev`, `libpq-dev`, `git`
2. Copies manifests only, creates dummy `main.rs` to cache dependency compilation
3. Builds dependencies with `RUSTFLAGS="-C target-cpu=native"` — this layer is cached until dependencies change
4. Removes dummy sources, copies actual source, rebuilds with production profile (`lto = true`, `codegen-units = 1`, `strip = true`)
5. Installs `cargo-audit` via `cargo install`
6. Pre-fetches the RustSec advisory database and pre-seeds the crates.io registry index

**Stage 2: Runtime** (same `rustlang/rust:nightly-slim`)
1. Installs runtime deps: `ca-certificates`, `libpq5`, `git`, `wget`
2. Copies `cargo-audit`, `cargo`, `rustc` to `/usr/local/bin/` — these survive the tmpfs mount over `/usr/local/cargo`
3. Copies advisory DB to `/advisory-db` — used with `cargo-audit --db /advisory-db`
4. Copies pre-seeded registry to `/cargo-seed/registry`
5. Downloads and installs `gitleaks` v8.21.2 (Go binary, not Rust)
6. Creates `/tmp/crates` directory, copies entrypoint script
7. `ENTRYPOINT ["/app/entrypoint.sh"]`, `CMD ["worker"]`

**Registry Pre-Seeding Strategy:**

The Docker image contains a pre-fetched crates.io registry index at `/cargo-seed/registry`. In the `docker-compose.workers.yml` configuration, the `registry-seeder` service copies this into a named Docker volume (`cargo-registry`) on first startup. Workers mount this volume at `/usr/local/cargo/registry` (read-write), so all `cargo update --workspace` calls within the container hit a local registry instead of downloading from the network.

### docker-compose.yml — Full Stack

```yaml
services:
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: crates
    ports: ["5432:5432"]
    volumes: [postgres_data:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s, timeout: 5s, retries: 5

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping || exit 1"]

  worker:
    build: { context: ., dockerfile: Dockerfile }
    command: worker
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }
    environment:
      - DATABASE_URL=postgres://postgres:postgres@postgres:5432/crates
      - REDIS_URL=redis://redis:6379
    tmpfs:
      - /tmp/crates:size=4g       # Crate source trees in RAM
      - /usr/local/cargo:size=2g   # Cargo home in RAM
    deploy:
      resources:
        limits: { cpus: '2', memory: 4G }
        reservations: { cpus: '0.5', memory: 1G }
```

Scale with: `docker-compose up -d --scale worker=50`

### docker-compose.workers.yml — Worker-Only Stack

Used when PostgreSQL and Redis run on the host machine:

```yaml
services:
  registry-seeder:
    # One-shot: copies /cargo-seed/registry → named volume
    restart: "no"

  worker:
    network_mode: "host"           # Connects to localhost Pg/Redis
    depends_on:
      registry-seeder: { condition: service_completed_successfully }
    environment:
      - DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/crates
      - REDIS_URL=redis://127.0.0.1:6379
    volumes:
      - /tmp/crates:/tmp/crates    # Host tmpfs mount (24G recommended)
      - ./logs/docker:/app/logs    # Persist logs
      - cargo-registry:/usr/local/cargo/registry  # Shared, pre-seeded
    tmpfs:
      - /usr/local/cargo/target:size=1g
      - /usr/local/cargo/git:size=256m
    restart: always
    deploy:
      resources:
        limits: { cpus: '1', memory: 4G }
```

Key differences from the full stack compose file:
- **Host networking**: workers connect to `127.0.0.1` directly (no Docker network overhead)
- **Named `cargo-registry` volume**: shared across all workers, seeded once by `registry-seeder`
- **Persistent logs**: mounted from host `./logs/docker`
- **Bounded tmpfs for target/git**: prevents unbounded `/usr/local/cargo` tmpfs consumption
- **Lower CPU limit**: 1 CPU per worker (vs 2 in full stack), suitable for more workers on fewer cores

### .dockerignore

Excludes from the Docker build context:
- `target/` (Rust build artifacts — huge)
- `.git/`, `.gitignore`
- IDE files (`.idea/`, `.vscode/`, swap files)
- `logs/`, `*.log`
- `db-dump/` (not needed by workers)
- Docker files, compose files, `.dockerignore`
- Documentation (`*.md`, `docs/`)
- CSV files

---

## 10. Shell Scripts

### `entrypoint.sh`
```bash
#!/bin/sh
mkdir -p /usr/local/cargo/git
exec /app/crates_downloader "$@"
```
Ensures `git/` dir exists in cargo home (required by cargo even when empty), then execs the binary.

### `reset-database.sh`
Full database reset: terminates connections, drops and recreates the `crates` database, runs all Diesel migrations. Validates prerequisites (`diesel` CLI, `psql`). Parses `DATABASE_URL` for connection components.

### `reset-all.sh`
Complete reset pipeline:
1. Clears `/tmp/crates/*`
2. Flushes Redis (`FLUSHALL`)
3. Runs `reset-database.sh`
4. Runs `cargo run --bin crates_downloader --release -- update-database`
5. Rebuilds Docker image
6. Runs `run-analysis` to rebuild the queue

### `start-workers.sh`
```bash
NUM_WORKERS=${1:-24}
sudo docker-compose -f docker-compose.workers.yml up -d --scale worker=$NUM_WORKERS
```
Starts N workers (default: 24). Usage: `./start-workers.sh [N]`.

### `start-timed.sh`
Starts N workers for H hours, then gracefully shuts them down via `docker-compose down`.
```bash
./start-timed.sh [workers] [hours]
# Default: 24 workers, 8 hours
```

### `docker-cleanup.sh`
Four-step cleanup:
1. Stops worker stack (`docker-compose down`)
2. Prunes stopped containers
3. Prunes dangling/unused images (force)
4. Prunes build cache (force)
With `--all`: also removes named project cache volumes.

### `mout-ramdisk.sh`
Creates and mounts a 24GB tmpfs at `/tmp/crates`:
```bash
sudo mkdir -p /tmp/crates
sudo mount -t tmpfs -o size=24G tmpfs /tmp/crates
df -h /tmp/crates
```

### `build-docker.sh`
```bash
sudo docker-compose -f docker-compose.workers.yml build
```

### `composer-down.sh`
```bash
sudo docker-compose -f docker-compose.workers.yml down
```

### `docker-logs.sh`
```bash
sudo docker-compose -f docker-compose.workers.yml logs | grep -i "error\|failed" | head -50
```
Displays the last 50 error/failure lines from worker logs.

### `analysis/run.sh`
Orchestrates the dissertation analysis pipeline:
1. Creates output directories (`output/plots`, `output/data`)
2. Runs `analyze.py` with configurable flags (`--skip-plots`, `--only-sql <number>`, `--db <url>`)
3. The Python script itself executes SQL queries via `psql --csv` and generates 15 matplotlib visualizations

---

## 11. Configuration

### `config.toml` (root default)

```toml
max_connections = 5
connection_string = "postgres://postgres:postgres@localhost:5432/crates"
llm_malicious_score_threshold = 75
update_source_data = true
use_only_first_x_crates = 0         # 0 = all crates
max_crates_downloads = 0
insert_crates_in_chunks = 1000
redis_url = "redis://localhost:6379"

# LLM (LM Studio)
lm_studio_url = "http://localhost:1234/v1"
lm_studio_model = "qwen/qwen2.5-coder-14b"
llm_max_tokens = 4096
llm_temperature = 0.1
llm_max_context_chars = 24576       # 24KB
llm_enabled = false
```

Environment variables (`DATABASE_URL`, `REDIS_URL`, `LM_STUDIO_URL`, `LM_STUDIO_MODEL`, `LLM_ENABLED`) override config file values at runtime.

### `crates_downloader/config.toml` (worker override)
Same structure but `update_source_data = false` and `insert_crates_in_chunks = 4000` (optimized for the worker context).

### `webpanel/config.toml`
```toml
connection_string = "postgres://postgres:postgres@localhost:5432/crates"
max_connections = 10
server_host = "0.0.0.0"
server_port = 3000
```

### Build Profile (`Cargo.toml` workspace)

```toml
[profile.production]
inherits = "release"
lto = true
codegen-units = 1
strip = true
overflow-checks = false
```

This profile is used in the Dockerfile builds for maximum runtime performance at the cost of compilation time.

---

## 12. Web Dashboard (`webpanel`)

An Axum-based web server serving a REST API and static frontend files.

### API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/api/stats` | GET | Aggregate ecosystem stats (counts, averages) |
| `/api/stats/severity` | GET | Vulnerability severity distribution |
| `/api/stats/risk` | GET | LLM risk score distribution (buckets) |
| `/api/stats/build-rs` | GET | Build.rs suspicious pattern counts |
| `/api/stats/top-downloaded` | GET | Top 10 most downloaded crates |
| `/api/stats/gitleaks-rules` | GET | Top 10 gitleaks rule occurrences |
| `/api/crates` | GET | Paginated crate listing with search/filter/sort |
| `/api/crates/{id}` | GET | Single crate detail |
| `/api/crates/name/{name}` | GET | Crate lookup by name |
| `/api/dependencies` | GET | Dependency listing with crate names resolved |
| `/api/scan-results` | GET | Scan results with extensive filtering |
| `/api/scan-results/{id}` | GET | Single scan result detail |
| `/api/cargo-audit` | GET | Vulnerability listing (RUSTSEC IDs, severity) |
| `/api/gitleaks` | GET | Secrets listing (rule, secret, location, entropy) |
| `/api/typosquat` | GET | Typosquat pairs with all similarity scores |
| `/api/metrics` | GET | Per-crate timing data |

All list endpoints support pagination (`page`, `per_page`), sorting (`sort_by`, `sort_desc`), and entity-specific filters.

### Frontend

A vanilla HTML/CSS/JS SPA with:
- **Dark theme** (`--bg-primary: #1a1a2e`, `--accent: #e94560`)
- **Sidebar navigation** (8 pages: Dashboard, Crates, Dependencies, Scan Results, Vulnerabilities, Secrets, Typosquat, Metrics)
- **Dashboard page**: 10 stat cards + 5 Chart.js visualizations (risk doughnut, severity bar, build.rs flags bar, top downloads bar, gitleaks rules bar)
- **Reusable `DataTable` component** in `api.js`: pagination, sorting, filtering, records-per-page selector, detail modals
- **Badge system**: Success/Warning/Danger/Info for severity and risk levels

---

## 13. Performance Estimates

Based on the SCALING.md analysis, assuming 30 seconds per crate:

| Workers | Concurrent Processing | Time for 10,000 crates |
|---------|----------------------|------------------------|
| 1 (no queue) | 30 | ~92 hours |
| 5 | 150 | ~18 hours |
| 10 | 300 | ~9 hours |
| 20 | 600 | ~4.5 hours |
| 50 | 1,500 | ~1.8 hours |

### Resource Requirements

- **PostgreSQL**: ~2GB RAM (scales with crate/dependency count)
- **Redis**: ~500MB RAM (dependency graph for 100k+ crates)
- **Per worker**: 1–2 CPU cores, 2–4GB RAM
- **tmpfs for `/tmp/crates`**: 4GB per active download (per worker, typically <1GB)
- **tmpfs for cargo**: 2GB (target/ and git/ are bounded at 1GB + 256MB)

---

## 14. Typical Workflow

### Local Development

```bash
# 1. Setup infrastructure
docker-compose up -d postgres redis

# 2. Create database and run migrations
./reset-database.sh

# 3. Download crates.io data and populate DB
cargo run --release -- update-database

# 4. Run typosquat detection
cargo run --release -- typosquat --min-score 75 --top-crates 10000

# 5. Queue analysis
cargo run --release -- run-analysis

# 6. Start workers (local processes)
cargo run --release -- worker &
cargo run --release -- worker &
# ... start N workers

# 7. Monitor progress
cargo run --release -- queue-status

# 8. Post-processing after completion
cargo run --release -- compute-dependencies

# 9. Start web dashboard
cd webpanel && cargo run --release
```

### Production (Docker)

```bash
# 1. Create RAM disk for crate downloads
./mout-ramdisk.sh

# 2. Setup infrastructure (if not using host Pg/Redis)
docker-compose up -d postgres redis

# 3. Initialize database
cargo run --release -- update-database

# 4. Queue analysis
cargo run --release -- run-analysis

# 5. Start timed workers (24 workers, 8 hours)
./start-timed.sh 24 8

# 6. Monitor
cargo run --release -- queue-status
./docker-logs.sh
```

### Crash Recovery

```bash
# If workers crash, recover stale in-progress items
cargo run --release -- recover-stale

# If queue is stuck (no ready items but not done), fix cycles
cargo run --release -- fix-cycles
cargo run --release -- break-cycles

# Restart workers
./start-workers.sh 24
```

---

## 15. Key Dependencies

### Rust (`crates_downloader`)
| Crate | Version | Purpose |
|-------|---------|---------|
| `diesel` | 2.3.2 | PostgreSQL ORM with async support |
| `diesel-async` | 0.7.3 | Async PostgreSQL via bb8 pool |
| `tokio` | 1.47 | Async runtime |
| `redis` | 0.32 | Redis client for queue management |
| `redis` (Lua) | — | Atomic queue operations |
| `clap` | 4.5 | CLI argument parsing |
| `reqwest` | 0.12 | HTTP client (crates.io download, LLM API) |
| `flate2` + `tar` | 1.1 / 0.4 | Archive extraction |
| `rayon` | 1.11 | Parallel typosquat detection |
| `walkdir` | 2.5 | Directory traversal for source files |
| `regex` | 1.10 | Pattern matching (build.rs analysis) |
| `sonic-rs` | 0.5 | Fast JSON parsing (cargo-audit, gitleaks output) |
| `tracing` | 0.1 | Structured logging |

### Rust (`webpanel`)
| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.7 | Web framework |
| `tower-http` | 0.6 | CORS, static file serving |
| `diesel` | 2.3 | PostgreSQL ORM |
| `serde` + `serde_json` | 1.0 | JSON serialization |

### External Tools (packaged in Docker image)
| Tool | Version | Purpose |
|------|---------|---------|
| `cargo-audit` | latest | RustSec vulnerability scanning |
| `gitleaks` | 8.21.2 | Secret detection |
| `git` | system | Repository cloning |

---

## 16. Analysis SQL Queries (Dissertation)

The `analysis/` directory contains 12 SQL files used to generate data for the thesis. Key queries:

| File | Focus |
|------|-------|
| `01_most_vulnerable_crates.sql` | Top crates by weighted risk_score (vuln count × avg severity) |
| `02_vuln_per_download_ratio.sql` | Vuln severity vs download popularity correlation |
| `03_typosquatting_analysis.sql` | Score distribution, high-risk pairs, download asymmetry |
| `04_secrets_leaked.sql` | Secrets by crate, rule type distribution, vuln+secret overlap |
| `05_build_rs_suspicious.sql` | Pattern prevalence, most-flagged crates, entropy distribution |
| `06_llm_score_correlation.sql` | LLM score buckets, LLM vs cargo-audit agreement matrix |
| `07_executable_files_analysis.sql` | Binary prevalence by download bracket, vuln overlap |
| `08_dependency_network.sql` | Most depended-upon crates, ecosystem risk (depended-on + vulnerable) |
| `09_temporal_analysis.sql` | Crate creation trend, vuln rate by age, download velocity |
| `10_ecosystem_overview.sql` | Key metrics, compound risk, worker performance stats |
| `crates_with_most_vulnerabilities.sql` | Recursive CTE for dependency chain analysis |
| `quick_reference.sql` | 8 quick reference queries |

The `analyze.py` script executes these queries via `psql --csv` and generates 15 matplotlib visualizations (PNG) including: vulnerable crate rankings, vuln-per-download scatter plots, typosquat score histograms, secret type distributions, build.rs flag analysis, LLM correlation matrices, severity pie charts, dependency centrality, temporal trends, executive prevalence, timing breakdowns, and compound risk bubble charts.
