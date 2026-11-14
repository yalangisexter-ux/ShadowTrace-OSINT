import type { CheckResult } from "./providers";

export interface UserRow {
  id: number;
  email: string;
  password_hash: string;
  created_at: string;
}

export interface SearchRunRow {
  id: number;
  user_id: number;
  query_type: string;
  query_value: string;
  created_at: string;
}

export interface EvidenceRow {
  id: number;
  run_id: number;
  provider: string;
  category: string | null;
  profile_url: string;
  status: string;
  http_status: number | null;
  confidence: string;
  detail: string;
  checked_at: string;
}

/**
 * Ensures required tables exist in Cloudflare D1.
 * Provides zero-friction initialization if migrations haven't run yet.
 */
export async function ensureSchema(db: D1Database): Promise<void> {
  const queries = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );`,
    `CREATE TABLE IF NOT EXISTS search_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      query_type TEXT NOT NULL DEFAULT 'username',
      query_value TEXT NOT NULL,
      created_at TEXT NOT NULL
    );`,
    `CREATE INDEX IF NOT EXISTS idx_search_runs_user_id ON search_runs(user_id);`,
    `CREATE INDEX IF NOT EXISTS idx_search_runs_created_at ON search_runs(created_at);`,
    `CREATE TABLE IF NOT EXISTS evidence (
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
    );`,
    `CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence(run_id);`,
    `CREATE TABLE IF NOT EXISTS rate_limits (bucket_key TEXT PRIMARY KEY, hit_count INTEGER NOT NULL, window_started_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);`,
    `CREATE INDEX IF NOT EXISTS idx_rate_limits_expires_at ON rate_limits(expires_at);`,
  ];
  for (const q of queries) {
    try {
      await db.prepare(q).run();
    } catch (e) {
      console.error("Schema query error:", e);
    }
  }
}

export async function getUserByEmail(db: D1Database, email: string): Promise<UserRow | null> {
  return db
    .prepare("SELECT * FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first<UserRow>();
}

export async function getUserById(db: D1Database, id: number): Promise<UserRow | null> {
  return db
    .prepare("SELECT id, email, password_hash, created_at FROM users WHERE id = ? LIMIT 1")
    .bind(id)
    .first<UserRow>();
}

export async function createUser(
  db: D1Database,
  email: string,
  passwordHash: string
): Promise<UserRow> {
  const createdAt = new Date().toISOString();
  const res = await db
    .prepare("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)")
    .bind(email, passwordHash, createdAt)
    .run();

  const id = res.meta.last_row_id as number;
  return { id, email, password_hash: passwordHash, created_at: createdAt };
}

/** Replace a password hash after a successful login-time rehash. */
export async function updatePasswordHash(db: D1Database, userId: number, passwordHash: string): Promise<void> {
  const result = await db
    .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .bind(passwordHash, userId)
    .run();
  if ((result.meta.changes ?? 0) !== 1) throw new Error("Unable to update password hash");
}

export async function createSearchRun(
  db: D1Database,
  userId: number,
  queryType: string,
  queryValue: string,
  evidence: CheckResult[]
): Promise<{ run: SearchRunRow; evidence: CheckResult[] }> {
  const createdAt = new Date().toISOString();
  const runRes = await db
    .prepare("INSERT INTO search_runs (user_id, query_type, query_value, created_at) VALUES (?, ?, ?, ?)")
    .bind(userId, queryType, queryValue, createdAt)
    .run();

  const runId = runRes.meta.last_row_id as number;

  if (evidence.length > 0) {
    const stmts = evidence.map((e) =>
      db
        .prepare(`
          INSERT INTO evidence (run_id, provider, category, profile_url, status, http_status, confidence, detail, checked_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          runId,
          e.provider,
          e.category,
          e.profile_url,
          e.status,
          e.http_status,
          e.confidence,
          e.detail,
          e.checked_at
        )
    );
    await db.batch(stmts);
  }

  const run: SearchRunRow = {
    id: runId,
    user_id: userId,
    query_type: queryType,
    query_value: queryValue,
    created_at: createdAt,
  };

  return { run, evidence };
}

export async function listUserRuns(
  db: D1Database,
  userId: number,
  limit: number = 50
): Promise<SearchRunRow[]> {
  const { results } = await db
    .prepare("SELECT id, query_type, query_value, created_at FROM search_runs WHERE user_id = ? ORDER BY id DESC LIMIT ?")
    .bind(userId, limit)
    .all<SearchRunRow>();
  return results || [];
}

export async function getRunDetails(
  db: D1Database,
  runId: number,
  userId: number
): Promise<{ run: SearchRunRow; evidence: EvidenceRow[] } | null> {
  const run = await db
    .prepare("SELECT * FROM search_runs WHERE id = ? AND user_id = ? LIMIT 1")
    .bind(runId, userId)
    .first<SearchRunRow>();

  if (!run) return null;

  const { results: evidence } = await db
    .prepare("SELECT * FROM evidence WHERE run_id = ? ORDER BY id ASC")
    .bind(runId)
    .all<EvidenceRow>();

  return { run, evidence: evidence || [] };
}
