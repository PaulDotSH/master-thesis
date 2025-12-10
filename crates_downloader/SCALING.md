# Distributed Crate Analysis Architecture

This document describes the high-performance, distributed architecture for analyzing Rust crates at scale with **dependency-aware processing**.

## Architecture Overview

```
┌─────────────┐
│  Producer   │  Builds dependency graph in Redis
│  (RunAnalysis)│ Crates with no deps go to ready queue
└─────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────┐
  │                     Redis                        │
  │  ┌─────────┐  ┌──────────────┐  ┌───────────┐  │
  │  │ Ready   │  │ In Progress  │  │ Completed │  │
  │  │ Queue   │  │    Set       │  │    Set    │  │
  │  └─────────┘  └──────────────┘  └───────────┘  │
  │       │                                         │
  │  ┌────────────────────────────────────────┐    │
  │  │ Dependency Graph (per-crate dep sets) │    │
  │  └────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────┘
       │
       ├──────┬──────┬──────────┐
       ▼      ▼      ▼          ▼
   ┌────┐  ┌────┐  ┌────┐    ┌────┐
   │ W1 │  │ W2 │  │ W3 │... │ WN │
   └────┘  └────┘  └────┘    └────┘
     ↓        ↓        ↓          ↓
        ┌──────────────────┐
        │    PostgreSQL    │
        └──────────────────┘
```

## Key Design Decisions

### 1. Dependency-Aware Processing (Topological Order)
- **How it works**: A crate becomes "ready" only when all its dependencies are processed
- **Benefit**: Dependencies are always analyzed before dependents
- **Implementation**: Redis tracks unprocessed deps per crate, updates dependents atomically

### 2. Redis Queue with Dependency Graph
- **Ready Queue**: Crates with no pending dependencies
- **In Progress Set**: Crates being processed by workers (atomic claim)
- **Completed Set**: Successfully processed crates
- **Per-crate dep sets**: Track which deps still need processing
- **Reverse index**: Know which crates depend on each crate

### 3. Atomic Operations
- Workers atomically claim crates (no double-processing)
- Completion updates dependents atomically (Lua scripts)
- Fault tolerant: Failed crates still allow dependents to proceed

### 4. Horizontal Scaling
- Scale from 1 to 50+ workers with a single command
- Each worker runs analysis modules sequentially on one crate at a time
- **No coordination overhead**: Redis handles all synchronization

## Usage

### Step 1: Setup Infrastructure
```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Or use existing infrastructure and update config.toml:
# redis_url = "redis://your-redis:6379"
# connection_string = "postgres://user:pass@host:5432/crates"
```

### Step 2: Initialize Database
```bash
cargo run --release -- update-database
```

### Step 3: Build Dependency Graph (Producer)
```bash
cargo run --release -- run-analysis
# Output: Dependency graph initialized: X ready immediately, Y with dependencies
```

### Step 4: Start Workers
```bash
# Option A: Local workers (development/testing)
cargo run --release -- worker &  # Start worker 1
cargo run --release -- worker &  # Start worker 2
cargo run --release -- worker &  # Start worker 3
# ... start as many as your machine can handle

# Option B: Docker workers (production)
docker-compose up -d --scale worker=10  # Scale to 10 workers

# Option C: Distributed workers across multiple machines
# On machine 1:
REDIS_URL=redis://central-redis:6379 cargo run --release -- worker

# On machine 2:
REDIS_URL=redis://central-redis:6379 cargo run --release -- worker

# On machine 3:
REDIS_URL=redis://central-redis:6379 cargo run --release -- worker
```

### Step 5: Monitor Progress
```bash
# Check queue status (built-in command)
cargo run --release -- queue-status

# Or check Redis directly
redis-cli LLEN crate:ready        # Ready to process
redis-cli SCARD crate:in_progress # Being processed
redis-cli SCARD crate:completed   # Done
redis-cli SCARD crate:failed      # Failed

# Watch worker logs
docker-compose logs -f worker

# Check database progress
psql -h localhost -U postgres -d crates -c "SELECT COUNT(*) FROM scan_results;"
```

### Step 6: Recovery (if workers crash)
```bash
# Recover in-progress items back to ready queue
cargo run --release -- recover-stale
```

### Step 7: Compute Dependencies (Post-Processing)
```bash
# After all workers complete
cargo run --release -- compute-dependencies
# This updates has_malicious_dependencies based on actual dependency analysis
```

## Performance Estimates

Assuming:
- Average crate analysis time: 30 seconds
- 10,000 crates to analyze

| Configuration | Parallelism | Total Time |
|---------------|-------------|------------|
| Single process (old) | 30 concurrent | ~92 hours |
| 5 workers | 150 concurrent | ~18 hours |
| 10 workers | 300 concurrent | ~9 hours |
| 20 workers | 600 concurrent | ~4.5 hours |
| 50 workers | 1500 concurrent | ~1.8 hours |

## Benefits Over Previous Architecture

### ✅ Dependency-Aware Processing
- Crates processed in topological order (dependencies first)
- `has_malicious_dependencies` can be computed during analysis (not just post-hoc)
- Better data quality and consistency

### ✅ No Double-Processing
- Atomic Redis operations ensure each crate processed exactly once
- Even with 50+ workers, no race conditions

### ✅ Fault Tolerance
- Worker crashes? Run `recover-stale` to move items back to ready queue
- Failed crate? Marked as failed, dependents can still proceed
- Redis persistence keeps state across restarts

### ✅ Easy Scaling
- Add more workers = linear speedup
- No code changes needed to scale
- Works across multiple machines

### ✅ Resumability
- Interrupt analysis anytime
- Resume by starting workers again - they pick up where they left off

## Configuration

Edit `config.toml`:

```toml
max_connections = 5
connection_string = "postgres://postgres:postgres@localhost:5432/crates"
redis_url = "redis://localhost:6379"
llm_malicious_score_threshold = 75
update_source_data = true
use_only_first_x_crates = 0  # 0 = all crates, N = top N by downloads
max_crates_downloads = 0
insert_crates_in_chunks = 1000
```

## Troubleshooting

### Workers not starting
- Check Redis connection: `redis-cli -u redis://your-redis:6379 ping`
- Check PostgreSQL connection: `psql -h host -U user -d crates`
- Verify config.toml has correct URLs

### Queue not emptying
- Check worker logs for errors
- Verify workers are running: `docker-compose ps`
- Check individual crate errors in logs

### Out of memory
- Reduce number of workers
- Each worker uses ~1-2GB RAM
- Adjust docker-compose.yml resource limits

### Slow analysis
- Check network speed (git clone is often the bottleneck)
- Verify cargo-audit and gitleaks are installed
- Consider using local crates.io mirror

## Advanced: Multi-Machine Setup

For analyzing 100k+ crates across multiple machines:

1. **Central Redis + PostgreSQL** (dedicated machine)
2. **N worker machines** (commodity hardware)

Each worker machine:
```bash
# Install Rust, cargo-audit, gitleaks
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cargo-audit
# Install gitleaks...

# Clone repo and build
git clone <repo>
cd master-thesis/crates_downloader
cargo build --release

# Configure
cat > config.toml <<EOF
connection_string = "postgres://user:pass@central-db:5432/crates"
redis_url = "redis://central-redis:6379"
# ... other settings
EOF

# Start multiple workers
for i in {1..10}; do
    cargo run --release -- worker &
done
```

This architecture allows you to utilize 100+ CPU cores across multiple machines for maximum throughput!

## Future Optimizations

1. **Pipeline batching**: Fetch multiple crates per worker iteration
2. **Local crate caching**: Share downloaded repos between workers
3. **Priority queue**: Analyze popular crates first (most dependencies)
4. **Result streaming**: Write results to object storage for better DB performance
5. **LLM optimization**: Batch LLM requests across multiple crates

