use anyhow::Context;
use redis::{aio::ConnectionManager, AsyncCommands, Script};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

// RDep graph management redis keys mapping
const READY_QUEUE: &str = "crate:ready"; // No pending deps
const IN_PROGRESS_SET: &str = "crate:in_progress";
const COMPLETED_SET: &str = "crate:completed";
const DEPS_PREFIX: &str = "crate:deps:"; // Hash: crate_id -> unprocessed dep IDs
const DEPENDENTS_PREFIX: &str = "crate:dependents:"; // Hash: crate_id -> crates that depend on it
const TOTAL_CRATES_KEY: &str = "crate:total";
const FAILED_SET: &str = "crate:failed";

// Crates become ready only when all its dependencies are completed
// Workers atomically claim ready crates
// When a crate completes, its dependents are checked and may become ready
// 
// crate:deps:<id> Unprocessed dependency IDs for each crate
// crate:dependents:<id> Crate IDs that depend on this crate


// WHITE = not visited, GRAY = in current path, BLACK = fully processed
const WHITE: u8 = 0;
const GRAY: u8 = 1;
const BLACK: u8 = 2;

pub struct WorkQueue {
    client: ConnectionManager,
}

impl WorkQueue {
    pub async fn new(redis_url: &str) -> Result<Self, anyhow::Error> {
        let client = redis::Client::open(redis_url)
            .context("Failed to create Redis client")?;
        let connection_manager = ConnectionManager::new(client)
            .await
            .context("Failed to create Redis connection manager")?;
        
        info!("Connected to Redis at {}", redis_url);
        Ok(Self {
            client: connection_manager,
        })
    }

    /// For each crate store the unprocessed dependencies
    /// For each dependency store which crates depend on it (reverse index)
    /// No deps = ready queue
    /// crate_ids - All crate IDs to process
    /// dependencies - Map of crate_id -> Vec<dependency_id>
    pub async fn initialize_dependency_graph(
        &mut self,
        crate_ids: &[i64],
        dependencies: &HashMap<i64, Vec<i64>>,
    ) -> Result<(), anyhow::Error> {
        info!("Initializing dependency graph for {} crates", crate_ids.len());
        
        // Clear state
        self.clear_all().await?;
        
        let _: () = self.client
            .set(TOTAL_CRATES_KEY, crate_ids.len())
            .await
            .context("Failed to set total crates count")?;
        
        // For fast lookup
        let crate_set: HashSet<i64> = crate_ids.iter().copied().collect();
        
        info!("Building filtered dependency graph...");
        let mut filtered_graph: HashMap<i64, HashSet<i64>> = HashMap::new();
        
        for &crate_id in crate_ids {
            let deps = dependencies.get(&crate_id);
            
            // Filter dependencies to only include crates we're processing
            // Also remove self-references
            let valid_deps: HashSet<i64> = deps
                .map(|d| d.iter()
                    .filter(|&&dep_id| crate_set.contains(&dep_id) && dep_id != crate_id)
                    .copied()
                    .collect())
                .unwrap_or_default();
            
            filtered_graph.insert(crate_id, valid_deps);
        }
        
        // Detect and break cycles using DFS
        info!("Detecting and breaking dependency cycles...");
        let edges = Self::find_cycle_edges(&filtered_graph);
        
        if !edges.is_empty() {
            info!("Found {} cycle edges to break upfront", edges.len());
            
            // Remove cycle edges from the filtered graph
            for (from, to) in &edges {
                if let Some(deps) = filtered_graph.get_mut(from) {
                    deps.remove(to);
                    debug!("Breaking cycle edge: {} -> {}", from, to);
                }
            }
        }
        
        // Store the new graph in Redis
        let mut ready_count = 0;
        let mut with_deps_count = 0;
        
        const BATCH_SIZE: usize = 1000;
        
        for chunk in crate_ids.chunks(BATCH_SIZE) {
            let mut pipe = redis::pipe();
            
            for &crate_id in chunk {
                let valid_deps = filtered_graph.get(&crate_id)
                    .map(|s| s.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                
                if valid_deps.is_empty() {
                    // No dependencies = Ready
                    pipe.rpush(READY_QUEUE, crate_id.to_string());
                    ready_count += 1;
                } else {
                    // Store unprocessed deps
                    let deps_key = format!("{}{}", DEPS_PREFIX, crate_id);
                    for dep_id in &valid_deps {
                        pipe.sadd(&deps_key, dep_id.to_string());
                    }
                    with_deps_count += 1;
                    
                    // Build reverse index; foreach dep this crate depends on it
                    for dep_id in &valid_deps {
                        let dependents_key = format!("{}{}", DEPENDENTS_PREFIX, dep_id);
                        pipe.sadd(&dependents_key, crate_id.to_string());
                    }
                }
            }
            
            let _: () = pipe.query_async(&mut self.client)
                .await
                .context("Failed to initialize dependency graph batch in Redis")?;
        }
        
        info!(
            "Dependency graph initialized: {} ready immediately, {} with dependencies, {} cycle edges broken",
            ready_count, with_deps_count, edges.len()
        );
        
        Ok(())
    }
    
    fn find_cycle_edges(graph: &HashMap<i64, HashSet<i64>>) -> Vec<(i64, i64)> {
        let mut color: HashMap<i64, u8> = HashMap::new();
        let mut cycle_edges: Vec<(i64, i64)> = Vec::new();
        
        // DFS function to find cycles
        fn find_cycles_dfs(
            node: i64,
            graph: &HashMap<i64, HashSet<i64>>,
            color: &mut HashMap<i64, u8>,
            edges: &mut Vec<(i64, i64)>,
        ) {
            color.insert(node, GRAY);
            
            if let Some(deps) = graph.get(&node) {
                for &dep in deps {
                    match color.get(&dep).copied().unwrap_or(WHITE) {
                        w if w == WHITE => {
                            // Not visited - recurse
                            find_cycles_dfs(dep, graph, color, edges);
                        }
                        g if g == GRAY => {
                            // Break the edge node -> dep
                            edges.push((node, dep));
                        }
                        _ => {}
                    }
                }
            }
            
            color.insert(node, BLACK);
        }
        
        // Run DFS from each unvisited node
        let nodes: Vec<i64> = graph.keys().copied().collect();
        for node in nodes {
            if color.get(&node).copied().unwrap_or(WHITE) == WHITE {
                find_cycles_dfs(node, graph, &mut color, &mut cycle_edges);
            }
        }
        
        cycle_edges
    }

    /// Pops a crate ID from the ready queue & adds it to in_progress
    pub async fn pop_ready_crate_atomic(&mut self) -> Result<Option<i64>, anyhow::Error> {
        // Lua script for atomic pop + add to in_progress
        let script = Script::new(r#"
            local crate_id = redis.call('LPOP', KEYS[1])
            if crate_id then
                redis.call('SADD', KEYS[2], crate_id)
                return crate_id
            end
            return nil
        "#);
        
        let result: Option<String> = script
            .key(READY_QUEUE)
            .key(IN_PROGRESS_SET)
            .invoke_async(&mut self.client)
            .await
            .context("Failed to pop ready crate")?;
        
        match result {
            Some(id_str) => {
                let crate_id: i64 = id_str.parse()
                    .context("Failed to parse crate ID from Redis")?;
                debug!("Popped ready crate {} from queue", crate_id);
                Ok(Some(crate_id))
            }
            None => Ok(None),
        }
    }

    /// pop_ready_crate but blocks if the queue is empty.
    pub async fn pop_ready_crate_blocking(&mut self, timeout_secs: f64) -> Result<Option<i64>, anyhow::Error> {
        if let Some(crate_id) = self.pop_ready_crate_atomic().await? {
            return Ok(Some(crate_id));
        }
        
        // Loop until we successfully claim a crate or timeout
        loop {
            // Use BLPOP with timeout
            let result: Option<(String, String)> = self.client
                .blpop(READY_QUEUE, timeout_secs)
                .await
                .context("Failed to block-pop from ready queue")?;
            
            match result {
                Some((_, id_str)) => {
                    let crate_id: i64 = id_str.parse()
                        .context("Failed to parse crate ID from Redis")?;
                    
                    let is_completed: bool = self.client
                        .sismember(COMPLETED_SET, &id_str)
                        .await
                        .context("Failed to check if crate is completed")?;
                    
                    if is_completed {
                        debug!("Skipping crate {} - already completed", crate_id);
                        continue;
                    }
                    
                    // SADD returns 1 if the element was added, 0 if it already existed
                    let added: i32 = self.client
                        .sadd(IN_PROGRESS_SET, &id_str)
                        .await
                        .context("Failed to add to in_progress set")?;
                    
                    if added == 0 {
                        debug!("Crate {} already claimed by another worker, trying next", crate_id);
                        continue;
                    }
                    
                    debug!("Block-popped and claimed ready crate {} from queue", crate_id);
                    return Ok(Some(crate_id));
                }
                None => return Ok(None), // Timeout
            }
        }
    }

    /// Mark a crate as completed and update its dependents
    /// Atomically remove the crate from in_progress, add to completed,
    /// remove the crate from the dependent crates deps, and add to redy queue dependents with no deps
    /// 
    pub async fn mark_completed(&mut self, crate_id: i64) -> Result<(), anyhow::Error> {
        let crate_id_str = crate_id.to_string();
        
        let script = Script::new(r#"
            local crate_id = ARGV[1]
            local deps_prefix = ARGV[2]
            local dependents_prefix = ARGV[3]
            local ready_queue = KEYS[1]
            local in_progress = KEYS[2]
            local completed = KEYS[3]
            
            -- Move in_progress to completed
            redis.call('SREM', in_progress, crate_id)
            redis.call('SADD', completed, crate_id)
            
            -- All crates that depend on this one
            local dependents_key = dependents_prefix .. crate_id
            local dependents = redis.call('SMEMBERS', dependents_key)
            
            local newly_ready = 0
            for _, dependent_id in ipairs(dependents) do
                -- Remove this crate from the dependent's unprocessed deps
                local deps_key = deps_prefix .. dependent_id
                redis.call('SREM', deps_key, crate_id)
                
                local remaining_deps = redis.call('SCARD', deps_key)
                if remaining_deps == 0 then
                    redis.call('RPUSH', ready_queue, dependent_id)
                    newly_ready = newly_ready + 1
                end
            end
            
            -- Clean up the dependents set for this crate
            redis.call('DEL', dependents_key)
            
            return newly_ready
        "#);
        
        let new_ready: i64 = script
            .key(READY_QUEUE)
            .key(IN_PROGRESS_SET)
            .key(COMPLETED_SET)
            .arg(&crate_id_str)
            .arg(DEPS_PREFIX)
            .arg(DEPENDENTS_PREFIX)
            .invoke_async(&mut self.client)
            .await
            .context("Failed to mark crate as completed")?;
        
        if new_ready > 0 {
            debug!("Crate {} completed, {} dependents now ready", crate_id, new_ready);
        } else {
            debug!("Crate {} completed", crate_id);
        }
        
        Ok(())
    }

    /// Mark a crate as failed, treat as completed for as dependency to prevent blocking other crates
    pub async fn mark_failed(&mut self, crate_id: i64) -> Result<(), anyhow::Error> {
        let crate_id_str = crate_id.to_string();
        
        let _: () = self.client
            .sadd(FAILED_SET, &crate_id_str)
            .await
            .context("Failed to add to failed set")?;
        
        self.mark_completed(crate_id).await?;
        
        warn!("Crate {} marked as failed", crate_id);
        Ok(())
    }

    pub async fn get_stats(&mut self) -> Result<QueueStats, anyhow::Error> {
        let pipe_result: (usize, usize, usize, usize, Option<usize>) = redis::pipe()
            .llen(READY_QUEUE)
            .scard(IN_PROGRESS_SET)
            .scard(COMPLETED_SET)
            .scard(FAILED_SET)
            .get(TOTAL_CRATES_KEY)
            .query_async(&mut self.client)
            .await
            .context("Failed to get queue stats")?;
        
        Ok(QueueStats {
            ready: pipe_result.0,
            in_progress: pipe_result.1,
            completed: pipe_result.2,
            failed: pipe_result.3,
            total: pipe_result.4.unwrap_or(0),
        })
    }

    pub async fn is_done(&mut self) -> Result<bool, anyhow::Error> {
        let stats = self.get_stats().await?;
        Ok(stats.completed + stats.failed >= stats.total && stats.in_progress == 0 && stats.ready == 0)
    }

    /// Moves items that have been in_progress for too long back to ready queue
    pub async fn recover_stale_items(&mut self) -> Result<usize, anyhow::Error> {
        // Get all in_progress items
        let in_progress: Vec<String> = self.client
            .smembers(IN_PROGRESS_SET)
            .await
            .context("Failed to get in_progress items")?;
        
        if in_progress.is_empty() {
            return Ok(0);
        }
        
        let mut recovered = 0;
        for crate_id_str in in_progress {
            // Push to ready queue if we successfully removed from in_progress
            let removed: i32 = self.client
                .srem(IN_PROGRESS_SET, &crate_id_str)
                .await
                .context("Failed to remove from in_progress")?;
            
            if removed > 0 {
                let _: () = self.client
                    .rpush(READY_QUEUE, &crate_id_str)
                    .await
                    .context("Failed to add back to ready queue")?;
                recovered += 1;
            }
        }
        
        if recovered > 0 {
            info!("Recovered {} stale items back to ready queue", recovered);
        }
        
        Ok(recovered)
    }

    /// Requeue a specific in-progress item back to the ready queue, used for shutdown
    pub async fn requeue_item(&mut self, crate_id: i64) -> Result<(), anyhow::Error> {
        let crate_id_str = crate_id.to_string();
        
        // Remove from in_progress
        let removed: i32 = self.client
            .srem(IN_PROGRESS_SET, &crate_id_str)
            .await
            .context("Failed to remove from in_progress")?;
        
        if removed > 0 {
            // Add back to ready queue with prio
            let _: () = self.client
                .lpush(READY_QUEUE, &crate_id_str)
                .await
                .context("Failed to add back to ready queue")?;
            info!("Requeued crate {} back to ready queue", crate_id);
        }
        
        Ok(())
    }

    /// Fix self-ref, on completed crates, break cycles, move ok deps to ready queue
    pub async fn fix_dependency_cycles(&mut self) -> Result<usize, anyhow::Error> {
        info!("Scanning for dependency cycles and stale dependencies...");
        
        // Get all crates that have pending dependencies
        let deps_keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{}*", DEPS_PREFIX))
            .query_async(&mut self.client)
            .await
            .context("Failed to get deps keys")?;
        
        info!("Found {} crates with pending dependencies", deps_keys.len());
        
        let mut self_refs_fixed = 0;
        let mut stale_deps_fixed = 0;
        let mut newly_ready = 0;
        
        // Fix self-refs and stale deps
        for deps_key in &deps_keys {
            let crate_id_str = deps_key.strip_prefix(DEPS_PREFIX).unwrap_or("");
            let crate_id: i64 = match crate_id_str.parse() {
                Ok(id) => id,
                Err(_) => continue,
            };
            
            let deps: Vec<String> = self.client
                .smembers(deps_key)
                .await
                .context("Failed to get deps")?;
            
            let mut deps_removed = 0;
            
            for dep_str in &deps {
                let dep_id: i64 = match dep_str.parse() {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                
                if dep_id == crate_id {
                    let _: () = self.client
                        .srem(deps_key, dep_str)
                        .await
                        .context("Failed to remove self-ref dep")?;
                    self_refs_fixed += 1;
                    deps_removed += 1;
                    debug!("Removed self-referential dependency for crate {}", crate_id);
                    continue;
                }
                
                let is_completed: bool = self.client
                    .sismember(COMPLETED_SET, dep_str)
                    .await
                    .context("Failed to check if dep is completed")?;
                
                if is_completed {
                    let _: () = self.client
                        .srem(deps_key, dep_str)
                        .await
                        .context("Failed to remove stale dep")?;
                    stale_deps_fixed += 1;
                    deps_removed += 1;
                    debug!("Removed stale dependency {} for crate {} (already completed)", dep_id, crate_id);
                }
            }
            
            // If we removed deps, check if this crate is now ready
            if deps_removed > 0 {
                let remaining: usize = self.client
                    .scard(deps_key)
                    .await
                    .context("Failed to get remaining deps count")?;
                
                if remaining == 0 {
                    let in_progress: bool = self.client
                        .sismember(IN_PROGRESS_SET, crate_id_str)
                        .await?;
                    let completed: bool = self.client
                        .sismember(COMPLETED_SET, crate_id_str)
                        .await?;
                    
                    if !in_progress && !completed {
                        let _: () = self.client
                            .rpush(READY_QUEUE, crate_id_str)
                            .await
                            .context("Failed to add to ready queue")?;
                        newly_ready += 1;
                        debug!("Crate {} is now ready (was blocked by cycles/stale deps)", crate_id);
                    }
                    
                    // Clean up the empty deps key
                    let _: () = self.client
                        .del(deps_key)
                        .await
                        .context("Failed to delete empty deps key")?;
                }
            }
        }
        
        info!(
            "Cycle fix complete: {} self-refs removed, {} stale deps removed, {} crates now ready",
            self_refs_fixed, stale_deps_fixed, newly_ready
        );
        
        Ok(newly_ready)
    }

    /// Break cycles using dfs and remove edge
    pub async fn break_complex_cycles(&mut self) -> Result<usize, anyhow::Error> {
        info!("Building dependency graph to detect complex cycles...");
        
        // Get all crates that have pending dependencies
        let deps_keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{}*", DEPS_PREFIX))
            .query_async(&mut self.client)
            .await
            .context("Failed to get deps keys")?;
        
        let mut graph: HashMap<i64, Vec<i64>> = HashMap::new();
        let pending_set: HashSet<String> = deps_keys.iter().cloned().collect();
        
        for deps_key in &deps_keys {
            let crate_id_str = deps_key.strip_prefix(DEPS_PREFIX).unwrap_or("");
            let crate_id: i64 = match crate_id_str.parse() {
                Ok(id) => id,
                Err(_) => continue,
            };
            
            let deps: Vec<String> = self.client
                .smembers(deps_key)
                .await
                .context("Failed to get deps")?;
            
            // Only track deps that are also pending
            let pending_deps: Vec<i64> = deps
                .iter()
                .filter_map(|s| {
                    let dep_key = format!("{}{}", DEPS_PREFIX, s);
                    if pending_set.contains(&dep_key) {
                        s.parse().ok()
                    } else {
                        None
                    }
                })
                .collect();
            
            graph.insert(crate_id, pending_deps);
        }
        
        info!("Graph has {} crates with pending-to-pending dependencies", graph.len());
        
        let mut color: HashMap<i64, u8> = HashMap::new();

        let mut edges: Vec<(i64, i64)> = Vec::new();
        
        fn find_cycles(
            node: i64,
            graph: &HashMap<i64, Vec<i64>>,
            color: &mut HashMap<i64, u8>,
            path: &mut Vec<i64>,
            edges: &mut Vec<(i64, i64)>,
        ) {
            color.insert(node, GRAY);
            path.push(node);
            
            if let Some(deps) = graph.get(&node) {
                for &dep in deps {
                    match color.get(&dep).copied().unwrap_or(WHITE) {
                        WHITE => {
                            find_cycles(dep, graph, color, path, edges);
                        }
                        GRAY => {
                            edges.push((node, dep));
                        }
                        _ => {}
                    }
                }
            }
            
            path.pop();
            color.insert(node, BLACK);
        }
        
        // Run DFS from each unvisited node
        let nodes: Vec<i64> = graph.keys().copied().collect();
        for node in nodes {
            if color.get(&node).copied().unwrap_or(WHITE) == WHITE {
                let mut path = Vec::new();
                find_cycles(node, &graph, &mut color, &mut path, &mut edges);
            }
        }
        
        info!("Found {} cycle edges to break", edges.len());
        
        // Remove cycle edges from Redis
        let mut cycles_broken = 0;
        for (from, to) in &edges {
            let deps_key = format!("{}{}", DEPS_PREFIX, from);
            let to_str = to.to_string();
            
            let removed: i64 = self.client
                .srem(&deps_key, &to_str)
                .await
                .context("Failed to remove cycle edge")?;
            
            if removed > 0 {
                cycles_broken += 1;
                info!("Broke cycle edge: {} -> {}", from, to);
                
                let remaining: usize = self.client
                    .scard(&deps_key)
                    .await
                    .context("Failed to get remaining deps")?;
                
                if remaining == 0 {
                    let from_str = from.to_string();
                    let in_progress: bool = self.client.sismember(IN_PROGRESS_SET, &from_str).await?;
                    let completed: bool = self.client.sismember(COMPLETED_SET, &from_str).await?;
                    
                    if !in_progress && !completed {
                        let _: () = self.client.rpush(READY_QUEUE, &from_str).await?;
                        info!("Crate {} is now ready after breaking cycle", from);
                    }
                    
                    let _: () = self.client.del(&deps_key).await?;
                }
            }
        }
        
        info!("Broke {} cycle edges", cycles_broken);
        Ok(cycles_broken)
    }

    /// Clear all queue state
    pub async fn clear_all(&mut self) -> Result<(), anyhow::Error> {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("crate:*")
            .query_async(&mut self.client)
            .await
            .context("Failed to get keys")?;
        
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut self.client)
                .await
                .context("Failed to delete keys")?;
            info!("Cleared {} Redis keys", keys.len());
        }
        
        Ok(())
    }

    // pub async fn ready_count(&mut self) -> Result<usize, anyhow::Error> {
    //     let len: usize = self.client
    //         .llen(READY_QUEUE)
    //         .await
    //         .context("Failed to get ready queue length")?;
    //     Ok(len)
    // }
}

#[derive(Debug, Clone)]
pub struct QueueStats {
    pub ready: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub total: usize,
}

impl std::fmt::Display for QueueStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let remaining = self.total.saturating_sub(self.completed + self.failed);
        let progress = if self.total > 0 {
            ((self.completed + self.failed) as f64 / self.total as f64) * 100.0
        } else {
            0.0
        };
        write!(
            f,
            "Progress: {:.1}% | Ready: {} | In Progress: {} | Completed: {} | Failed: {} | Remaining: {} / {}",
            progress, self.ready, self.in_progress, self.completed, self.failed, remaining, self.total
        )
    }
}

