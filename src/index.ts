import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  PROVIDERS,
  providerCount,
  searchUsername,
  validateUsername,
} from "./providers";
import {
  createAccessToken,
  decodeAccessToken,
  hashPassword,
  verifyPassword,
} from "./security";
import {
  createUser,
  createSearchRun,
  ensureSchema,
  getRunDetails,
  getUserByEmail,
  getUserById,
  listUserRuns,
  type UserRow,
} from "./db";

export interface Env {
  DB: D1Database;
  SECRET_KEY?: string;
  APP_ENV?: string;
  ACCESS_TOKEN_MINUTES?: string;
  CORS_ORIGINS?: string;
  ASSETS?: Fetcher;
}

type Variables = {
  user: UserRow;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Simple in-memory sliding window rate limiter
const attempts = new Map<string, number[]>();

function throttle(key: string, limit: number, windowSeconds: number): void {
  const now = Date.now() / 1000;
  let q = attempts.get(key) || [];
  q = q.filter((t) => now - t <= windowSeconds);
  if (q.length >= limit) {
    throw new Error("Too many requests. Try again shortly.");
  }
  q.push(now);
  attempts.set(key, q);
}

// CORS Middleware
app.use("*", async (c, next) => {
  const origins = (c.env.CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (origins.length > 0) {
    return cors({
      origin: origins,
      allowHeaders: ["Authorization", "Content-Type"],
      allowMethods: ["GET", "POST", "OPTIONS"],
      credentials: true,
    })(c, next);
  }
  await next();
});

// Middleware: auto ensure schema exists in D1
let schemaInitialized = false;
app.use("/api/*", async (c, next) => {
  if (!schemaInitialized && c.env.DB) {
    try {
      await ensureSchema(c.env.DB);
      schemaInitialized = true;
    } catch (e) {
      console.error("DB init error:", e);
    }
  }
  await next();
});

// Helper: resolve secret key
function getSecretKey(env: Env): string {
  return env.SECRET_KEY || "local-development-only-change-me";
}

// Helper: extract authenticated user
async function requireAuth(c: any): Promise<UserRow> {
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    c.status(401);
    throw new Error("Bearer token required");
  }
  const token = authHeader.slice(7).trim();
  const secret = getSecretKey(c.env);
  const userId = await decodeAccessToken(token, secret);
  if (!userId) {
    c.status(401);
    throw new Error("Invalid or expired token");
  }

  const user = await getUserById(c.env.DB, userId);
  if (!user) {
    c.status(401);
    throw new Error("Invalid or expired token");
  }
  return user;
}

// Email regex
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Health check endpoint
app.get("/healthz", async (c) => {
  const secretKey = getSecretKey(c.env);
  const secretOk =
    secretKey !== "local-development-only-change-me" && secretKey.length >= 32;
  const dbOk = Boolean(c.env.DB);
  const status = secretOk && dbOk ? "ok" : "degraded";

  return c.json({
    status,
    service: "shadowtrace-osint",
    version: "0.2.0-cloudflare",
    providers: providerCount(),
    time: new Date().toISOString(),
    config: {
      secret_key_set: secretOk,
      database_configured: dbOk,
      app_env: c.env.APP_ENV || "production",
      platform: "cloudflare-workers",
    },
  });
});

// Auth: Register
app.post("/api/v1/auth/register", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  if (!EMAIL_RE.test(email)) {
    return c.json({ detail: "Invalid email address format" }, 422);
  }
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    return c.json(
      { detail: "Password must be between 12 and 128 characters long" },
      422
    );
  }

  try {
    throttle(`register:${email}`, 3, 3600);
  } catch (err: any) {
    return c.json({ detail: err.message }, 429);
  }

  const existing = await getUserByEmail(c.env.DB, email);
  if (existing) {
    return c.json({ detail: "An account with this email already exists" }, 409);
  }

  const passwordHash = await hashPassword(password);
  const user = await createUser(c.env.DB, email, passwordHash);

  const secret = getSecretKey(c.env);
  const minutes = parseInt(c.env.ACCESS_TOKEN_MINUTES || "60", 10) || 60;
  const token = await createAccessToken(user.id, secret, minutes);

  return c.json(
    {
      access_token: token,
      token_type: "bearer",
    },
    201
  );
});

// Auth: Login
app.post("/api/v1/auth/login", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  try {
    throttle(`login:${email}`, 8, 300);
  } catch (err: any) {
    return c.json({ detail: err.message }, 429);
  }

  const user = await getUserByEmail(c.env.DB, email);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ detail: "Invalid email or password" }, 401);
  }

  const secret = getSecretKey(c.env);
  const minutes = parseInt(c.env.ACCESS_TOKEN_MINUTES || "60", 10) || 60;
  const token = await createAccessToken(user.id, secret, minutes);

  return c.json({
    access_token: token,
    token_type: "bearer",
  });
});

// Auth: Me
app.get("/api/v1/auth/me", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  return c.json({
    id: user.id,
    email: user.email,
    created_at: user.created_at,
  });
});

// Search: Username investigation
app.post("/api/v1/search/username", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  let username: string;
  try {
    username = validateUsername(body.username || "");
  } catch (err: any) {
    return c.json({ detail: err.message }, 422);
  }

  try {
    throttle(`search:${user.id}`, 4, 60);
  } catch (err: any) {
    return c.json({ detail: err.message }, 429);
  }

  // Concurrent OSINT profile lookup across providers via Cloudflare subrequests
  const results = await searchUsername(username);

  // Store run and evidence in D1
  const { run } = await createSearchRun(c.env.DB, user.id, username, results);

  const candidates = results.filter((r) => r.status === "candidate").length;

  return c.json(
    {
      id: run.id,
      query_type: run.query_type,
      query_value: run.query_value,
      created_at: run.created_at,
      summary: {
        total: results.length,
        candidates,
        providers: providerCount(),
      },
      evidence: results,
      notice:
        "Candidate matches are not identity verification. Review each source manually.",
    },
    201
  );
});

// Search: List past investigations
app.get("/api/v1/search/runs", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runs = await listUserRuns(c.env.DB, user.id, 50);
  return c.json(
    runs.map((r) => ({
      id: r.id,
      query_type: r.query_type,
      query_value: r.query_value,
      created_at: r.created_at,
    }))
  );
});

// Search: Get run details
app.get("/api/v1/search/runs/:run_id", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  return c.json({
    id: data.run.id,
    query_type: data.run.query_type,
    query_value: data.run.query_value,
    created_at: data.run.created_at,
    evidence: data.evidence.map((e) => ({
      provider: e.provider,
      category: e.category,
      profile_url: e.profile_url,
      status: e.status,
      http_status: e.http_status,
      confidence: e.confidence,
      detail: e.detail,
      checked_at: e.checked_at,
    })),
  });
});

// Search: Markdown report export
app.get("/api/v1/search/runs/:run_id/report.md", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const lines = [
    `# ShadowTrace Investigation Report`,
    ``,
    `**Query:** \`${data.run.query_value}\` (${data.run.query_type})`,
    `**Run ID:** ${data.run.id}`,
    `**Created:** ${data.run.created_at}`,
    ``,
    `## Results`,
    ``,
  ];

  const sortedEvidence = [...data.evidence].sort((a, b) => {
    const aIsCand = a.status === "candidate" ? 0 : 1;
    const bIsCand = b.status === "candidate" ? 0 : 1;
    if (aIsCand !== bIsCand) return aIsCand - bIsCand;
    return a.provider.localeCompare(b.provider);
  });

  for (const e of sortedEvidence) {
    lines.push(`### ${e.provider}`);
    lines.push(`- Status: **${e.status}** (confidence: ${e.confidence})`);
    lines.push(`- URL: ${e.profile_url}`);
    lines.push(`- HTTP: ${e.http_status ?? "—"}`);
    lines.push(`- Detail: ${e.detail}`);
    lines.push(`- Checked: ${e.checked_at}`);
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(
    `Candidate matches are not proof of identity. Manually verify every source.`
  );
  lines.push(`Generated by ShadowTrace OSINT on Cloudflare Workers — public-source only.`);

  return c.text(lines.join("\n"), 200, {
    "Content-Type": "text/markdown; charset=utf-8",
  });
});

// Unmatched routes
app.notFound((c) => {
  return c.json({ detail: "Not Found" }, 404);
});

export default app;
