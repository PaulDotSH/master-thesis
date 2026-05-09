-- Restore entropy_score metric on rollback
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS entropy_score REAL NOT NULL DEFAULT 0.0;
