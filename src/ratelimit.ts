export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
}

/** Atomic fixed-window limiter shared by every Worker instance through D1. */
export async function consumeRateLimit(
  db: D1Database,
  key: string,
  limit: number,
  windowSeconds: number,
  now = Date.now()
): Promise<RateLimitDecision> {
  if (!key || key.length > 200) throw new Error("Invalid rate-limit key");
  if (!Number.isInteger(limit) || limit < 1 || !Number.isInteger(windowSeconds) || windowSeconds < 1) {
    throw new Error("Invalid rate-limit policy");
  }
  const expiresAt = now + windowSeconds * 1000;
  const row = await db.prepare(`
    INSERT INTO rate_limits (bucket_key, hit_count, window_started_at, expires_at)
    VALUES (?, 1, ?, ?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      hit_count = CASE WHEN rate_limits.expires_at <= ? THEN 1 ELSE rate_limits.hit_count + 1 END,
      window_started_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.window_started_at ELSE rate_limits.window_started_at END,
      expires_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.expires_at ELSE rate_limits.expires_at END
    RETURNING hit_count, expires_at
  `).bind(key, now, expiresAt, now, now, now).first<{hit_count:number;expires_at:number}>();
  if (!row) throw new Error("Rate limiter unavailable");
  const allowed = row.hit_count <= limit;
  return {
    allowed,
    limit,
    remaining: Math.max(0, limit - row.hit_count),
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((row.expires_at - now) / 1000))
  };
}

/** Periodically call after a successful request; deletion is bounded to avoid long D1 scans. */
export async function pruneRateLimits(db: D1Database, now = Date.now()): Promise<void> {
  await db.prepare("DELETE FROM rate_limits WHERE bucket_key IN (SELECT bucket_key FROM rate_limits WHERE expires_at <= ? LIMIT 500)")
    .bind(now).run();
}
