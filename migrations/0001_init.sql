-- Migration 0001: Initial schema for ShadowTrace OSINT on Cloudflare D1

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS search_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    query_type TEXT NOT NULL DEFAULT 'username',
    query_value TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_search_runs_user_id ON search_runs(user_id);
CREATE INDEX IF NOT EXISTS idx_search_runs_created_at ON search_runs(created_at);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    category TEXT,
    profile_url TEXT NOT NULL,
    status TEXT NOT NULL,
    http_status INTEGER,
    confidence TEXT NOT NULL,
    detail TEXT NOT NULL,
    checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence(run_id);
