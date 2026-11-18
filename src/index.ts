import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  ensureSchema,
  getUserById,
  getUserByEmail,
  createUser,
  updatePasswordHash,
  createSearchRun,
  listUserRuns,
  getRunDetails,
  type UserRow,
} from "./db.ts";
import { consumeRateLimit, pruneRateLimits } from "./ratelimit.ts";
import {
  hashPassword,
  verifyPassword,
  createAccessToken,
  decodeAccessToken,
} from "./security.ts";
import { validateUsername } from "./providers.ts";
import { checkPasswordExposure } from "./breach.ts";
import { validateSearchInput, type SearchType } from "./search.ts";
import { collectorManager } from "./collector.ts";
import { buildKnowledgeGraph } from "./graph.ts";
import { generateAISummary } from "./ai.ts";
import { generateMarkdownReport, generateCSVReport, generateHTMLReport } from "./report.ts";

function getSecretKey(env: Env): string {
  return env.SECRET_KEY || "fallback-secret-key-32-chars-long-minimum";
}

function validatePasswordStrength(password: string): string | null {
  if (typeof password !== "string" || password.length < 8) {
    return "Password must be at least 8 characters long";
  }
  return null;
}

export interface Env {
  DB: D1Database;
  SECRET_KEY: string;
  APP_ENV?: string;
  ACCESS_TOKEN_MINUTES?: string;
  ASSETS?: Fetcher;
}

export const app = new Hono<{ Bindings: Env }>();

// Security headers
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header(
    "Permissions-Policy",
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
  );
  if (c.env.APP_ENV === "production") {
    c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
});

// Global CORS allowlist
app.use(
  "/api/*",
  cors({
    origin: (origin) => {
      if (!origin) return "*";
      if (
        origin.endsWith(".workers.dev") ||
        origin.endsWith(".pages.dev") ||
        origin === "http://localhost:8000" ||
        origin === "http://127.0.0.1:8000" ||
        origin === "http://localhost:8787" ||
        origin === "http://127.0.0.1:8787" ||
        origin === "http://localhost:3000"
      ) {
        return origin;
      }
      return "*";
    },
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400,
  })
);

// Durable D1-backed rate limiting shared across Worker instances
async function checkThrottle(db: D1Database | undefined, key: string, limit: number, windowSeconds: number) {
  if (!db) return { allowed: true, limit, remaining: limit, retryAfterSeconds: 0 };
  return consumeRateLimit(db, key, limit, windowSeconds);
}

// Global error handler
app.onError((err, c) => {
  console.error("Unhandled Worker Exception:", err);
  const status = (c.res?.status && c.res.status >= 400 && c.res.status < 600) ? c.res.status : 500;
  return c.json({
    detail: err.message || "Internal server error occurred",
    status: "error",
    timestamp: new Date().toISOString()
  }, status as any);
});

// Middleware: auto-initialize D1 schema on first request
let schemaInitialized = false;
app.use("*", async (c, next) => {
  if (!schemaInitialized && c.env.DB) {
    try {
      await ensureSchema(c.env.DB);
      schemaInitialized = true;
    } catch (e) {
      console.error("Schema init warning:", e);
    }
  }
  await next();
});

// Landing page / static frontend
app.get("/", async (c) => {
  if (c.env.ASSETS) {
    try {
      const assetRes = await c.env.ASSETS.fetch(c.req.raw);
      if (assetRes.status === 200) return assetRes;
    } catch {
      // Fallback to embedded response
    }
  }
  return c.json({
    name: "ShadowTrace OSINT Platform",
    version: "2.0.0",
    architecture: "Next-Gen Modular AI-Powered OSINT Engine",
    modules: ["domain", "ip", "email", "username", "phone", "crypto", "metadata"],
    status: "healthy",
  });
});

// Auth helper
async function requireAuth(c: any): Promise<UserRow> {
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("Missing or invalid authorization header");
  }
  const token = authHeader.slice(7).trim();
  const secret = getSecretKey(c.env);
  const userId = await decodeAccessToken(token, secret);
  if (!userId) {
    throw new Error("Invalid or expired session token");
  }
  const user = await getUserById(c.env.DB, userId);
  if (!user) {
    throw new Error("Account not found");
  }
  return user;
}

// Threat Matrix calculation
function calculateThreatMatrix(results: any[], queryType: string) {
  const verified = results.filter((r) => r.status === "candidate" && r.verified === true);
  const verifiedCount = verified.length;
  const breachCount = results.filter(r => r.verified === true && r.status === "candidate" && /breach|pwned|leak/i.test(r.provider)).length;
  let baseScore = 0;
  if (queryType === "domain") {
    const hasSpfIssue = results.some((r) => r.detail && r.detail.includes("MISSING"));
    baseScore = hasSpfIssue ? 65 : 20;
  } else {
    baseScore = Math.min(85, verifiedCount * 8 + breachCount * 25 + 15);
  }
  let threatLevel: "LOW" | "MODERATE" | "ELEVATED" | "HIGH" | "CRITICAL" = "LOW";
  if (baseScore >= 75) threatLevel = "CRITICAL";
  else if (baseScore >= 55) threatLevel = "HIGH";
  else if (baseScore >= 35) threatLevel = "ELEVATED";
  else if (baseScore >= 15) threatLevel = "MODERATE";

  return {
    score: baseScore,
    overall_threat_score: baseScore,
    level: threatLevel,
    risk_level: threatLevel.toLowerCase(),
    exposure_summary: `${verifiedCount} high-confidence public identity signals; ${results.length - verifiedCount} unverified records excluded`,
    credential_reuse_risk: verifiedCount > 2 ? "Potential (multiple verified public accounts; password reuse not established)" : "Not established",
    phishing_surface: queryType === "email" || queryType === "phone" ? "Potential communication vector; not proof of compromise" : "Moderate",
  };
}

// Health check endpoint
app.get("/healthz", async (c) => {
  const secretKey = getSecretKey(c.env);
  const secretOk = secretKey.length >= 32;
  let dbOk = false;
  if (c.env.DB) {
    try {
      await c.env.DB.prepare("SELECT 1").first();
      dbOk = true;
    } catch {
      dbOk = false;
    }
  }

  const isHealthy = secretOk && dbOk;
  return c.json(
    {
      status: isHealthy ? "ok" : "degraded",
      service: "shadowtrace-osint",
      version: "2.0.0",
      architecture: "Modular Multi-Collector Engine",
      config: {
        secret_key_set: secretOk,
        database_configured: dbOk,
        app_env: c.env.APP_ENV || "unknown",
      },
    },
    isHealthy ? 200 : 503
  );
});

// Plugin / Collector Registry inspection endpoint
app.get("/api/v1/plugins", async (c) => {
  const plugins = collectorManager.listPlugins();
  const health = await collectorManager.checkHealth();
  return c.json({
    total: plugins.length,
    plugins: plugins.map(p => ({
      ...p,
      status: health[p.id]?.ok ? "active" : "degraded",
      health: health[p.id] || { ok: true },
    })),
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

  const clientIp = c.req.header("cf-connecting-ip") || "anon";
  const throttle = await checkThrottle(c.env.DB, "auth:register:" + clientIp, 5, 300);
  if (!throttle.allowed) {
    return c.json({ detail: "Too many registration attempts. Try again later.", retry_after: throttle.retryAfterSeconds }, 429);
  }

  const accountId = typeof body.username === "string" ? body.username.trim().toLowerCase() : (typeof body.email === "string" ? body.email.trim().toLowerCase() : "");
  if (!accountId || accountId.length < 3) {
    return c.json({ detail: "Username or email must be at least 3 characters" }, 422);
  }

  const passwordError = validatePasswordStrength(body.password);
  if (passwordError) {
    return c.json({ detail: passwordError }, 422);
  }

  const existing = await getUserByEmail(c.env.DB, accountId);
  if (existing) {
    return c.json({ detail: "Account already registered" }, 409);
  }

  const passwordHash = await hashPassword(body.password);
  const user = await createUser(c.env.DB, accountId, passwordHash);
  const secret = getSecretKey(c.env);
  const minutes = parseInt(c.env.ACCESS_TOKEN_MINUTES || "60", 10) || 60;
  const token = await createAccessToken(user.id, secret, minutes);

  return c.json({ access_token: token, token_type: "bearer" }, 201);
});

// Auth: Login
app.post("/api/v1/auth/login", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  const clientIp = c.req.header("cf-connecting-ip") || "anon";
  const throttle = await checkThrottle(c.env.DB, "auth:login:" + clientIp, 10, 60);
  if (!throttle.allowed) {
    return c.json({ detail: "Too many login attempts. Try again shortly.", retry_after: throttle.retryAfterSeconds }, 429);
  }

  const accountId = typeof body.username === "string" ? body.username.trim().toLowerCase() : (typeof body.email === "string" ? body.email.trim().toLowerCase() : "");
  const password = typeof body.password === "string" ? body.password : "";
  if (!accountId || !password) {
    return c.json({ detail: "Username/email and password required" }, 422);
  }

  const user = await getUserByEmail(c.env.DB, accountId);
  if (!user) {
    return c.json({ detail: "Invalid credentials" }, 401);
  }

  const verification = await verifyPassword(password, user.password_hash);
  if (!verification.ok) {
    return c.json({ detail: "Invalid credentials" }, 401);
  }

  if (verification.needsRehash) {
    const upgraded = await hashPassword(password);
    await updatePasswordHash(c.env.DB, user.id, upgraded);
  }

  const secret = getSecretKey(c.env);
  const minutes = parseInt(c.env.ACCESS_TOKEN_MINUTES || "60", 10) || 60;
  const token = await createAccessToken(user.id, secret, minutes);

  return c.json({ access_token: token, token_type: "bearer" });
});

// Auth: Current User
app.get("/api/v1/auth/me", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }
  return c.json({ id: user.id, username: user.email, email: user.email, created_at: user.created_at });
});

// Password exposure check
app.post("/api/v1/security/password-exposure", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  const clientIp = c.req.header("cf-connecting-ip") || "anon";
  const throttle = await checkThrottle(c.env.DB, "security:pwd-exposure:" + clientIp, 10, 60);
  if (!throttle.allowed) return c.json({ detail: "Rate limit exceeded. Try again shortly." }, 429);

  if (typeof body.password !== "string" || !body.password) {
    return c.json({ detail: "Password string required" }, 422);
  }

  const expRes = await checkPasswordExposure(body.password);
  return c.json({ exposed: expRes.exposed, count: expRes.exposureCount });
});

// Unified Search Handler (Supports username, phone, email, domain, ip, crypto, metadata)
async function handleSearch(c: any) {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  let validatedQuery: { type: SearchType; value: string };
  try {
    validatedQuery = validateSearchInput(body.username ?? body.query, body.type);
  } catch (err: any) {
    return c.json({ detail: err.message || "Invalid search query" }, 422);
  }
  const rawQuery = validatedQuery.value;
  const searchType = validatedQuery.type;

  // Check authentication (optional, guest allowed with rate limits)
  let user: UserRow | null = null;
  const authHeader = c.req.header("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    try {
      const token = authHeader.slice(7).trim();
      const secret = getSecretKey(c.env);
      const userId = await decodeAccessToken(token, secret);
      if (userId) {
        user = await getUserById(c.env.DB, userId);
      }
    } catch {
      // Proceed as guest
    }
  }

  const clientIp = c.req.header("cf-connecting-ip") || "anon";
  const searchLimit = user
    ? await checkThrottle(c.env.DB, "search:user:" + user.id, 25, 60)
    : await checkThrottle(c.env.DB, "search:guest:" + clientIp, 25, 60);
  if (!searchLimit.allowed) {
    return c.json({ detail: "Search rate limit exceeded. Try again shortly.", retry_after: searchLimit.retryAfterSeconds }, 429);
  }

  // Dispatch to the unified Collector Manager
  const depth = parseInt(body.depth || "0", 10) || 0;
  const collectionResult = await collectorManager.dispatch(rawQuery, searchType, { depth });

  const queryLabel = collectionResult.label || rawQuery;
  const entities = collectionResult.entities;
  const results = collectionResult.evidence;
  const candidates = results.filter((r) => r.status === "candidate").length;

  const threatMatrix = calculateThreatMatrix(results, searchType);
  const graph = buildKnowledgeGraph(queryLabel, searchType, entities, results);
  const aiSummary = generateAISummary(queryLabel, searchType, entities, results, threatMatrix);

  let runId = Date.now();
  let createdAt = new Date().toISOString();

  // If authenticated and DB available, persist run
  if (user && c.env.DB) {
    try {
      const dbEvidence = results.map(r => ({
        provider: r.provider,
        category: r.category || "identity",
        profile_url: r.profile_url || "",
        domain: r.domain || "",
        status: r.status,
        http_status: r.http_status ?? null,
        confidence: r.confidence === "high" ? ("high" as const) : ("low" as const),
        detail: r.detail || "",
        checked_at: r.checked_at,
      }));
      const { run } = await createSearchRun(c.env.DB, user.id, searchType, queryLabel, dbEvidence);
      runId = run.id;
      createdAt = run.created_at;
    } catch (e) {
      console.error("Run save warning:", e);
    }
  }

  return c.json(
    {
      id: runId,
      query_type: searchType,
      query_value: queryLabel,
      created_at: createdAt,
      entities,
      summary: {
        total: results.length,
        candidates,
        providers: results.length,
      },
      threat_matrix: threatMatrix,
      evidence: results,
      graph,
      ai: aiSummary,
      notice: "Candidate matches are derived from public OSINT telemetry. Manually verify identity ownership before acting on evidence.",
    },
    201
  );
}

// Unified search routes
app.post("/api/v1/search/username", handleSearch);
app.post("/api/v1/search", handleSearch);

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

  const threatMatrix = calculateThreatMatrix(data.evidence, data.run.query_type);
  const graph = buildKnowledgeGraph(data.run.query_value, data.run.query_type, {}, data.evidence);
  const aiSummary = generateAISummary(data.run.query_value, data.run.query_type, {}, data.evidence, threatMatrix);

  return c.json({
    id: data.run.id,
    query_type: data.run.query_type,
    query_value: data.run.query_value,
    created_at: data.run.created_at,
    threat_matrix: threatMatrix,
    graph,
    ai: aiSummary,
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

// Search: Knowledge Graph JSON Export
app.get("/api/v1/search/runs/:run_id/graph.json", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) return c.json({ detail: "Investigation not found" }, 404);

  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) return c.json({ detail: "Investigation not found" }, 404);

  const graph = buildKnowledgeGraph(data.run.query_value, data.run.query_type, {}, data.evidence);
  return c.json(graph);
});

// Search: AI Summary JSON Export
app.get("/api/v1/search/runs/:run_id/ai-summary", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) return c.json({ detail: "Investigation not found" }, 404);

  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) return c.json({ detail: "Investigation not found" }, 404);

  const threatMatrix = calculateThreatMatrix(data.evidence, data.run.query_type);
  const aiSummary = generateAISummary(data.run.query_value, data.run.query_type, {}, data.evidence, threatMatrix);
  return c.json(aiSummary);
});

// Helper to construct report data
async function getReportData(c: any, runId: number, user: UserRow) {
  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) return null;
  const threatMatrix = calculateThreatMatrix(data.evidence, data.run.query_type);
  const ai = generateAISummary(data.run.query_value, data.run.query_type, {}, data.evidence, threatMatrix);
  return {
    id: data.run.id,
    queryType: data.run.query_type,
    queryValue: data.run.query_value,
    createdAt: data.run.created_at,
    entities: {},
    summary: {
      total: data.evidence.length,
      candidates: data.evidence.filter(e => e.status === "candidate").length,
      providers: data.evidence.length,
    },
    threatMatrix,
    evidence: data.evidence,
    ai,
  };
}

// Markdown Report Export
app.get("/api/v1/search/runs/:run_id/report.md", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) return c.json({ detail: "Investigation not found" }, 404);

  const reportData = await getReportData(c, runId, user);
  if (!reportData) return c.json({ detail: "Investigation not found" }, 404);

  const md = generateMarkdownReport(reportData);
  return c.text(md, 200, {
    "Content-Type": "text/markdown; charset=utf-8",
    "Content-Disposition": `attachment; filename="shadowtrace-report-${runId}.md"`,
    "Cache-Control": "private, no-store",
  });
});

// CSV Report Export
app.get("/api/v1/search/runs/:run_id/report.csv", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) return c.json({ detail: "Investigation not found" }, 404);

  const reportData = await getReportData(c, runId, user);
  if (!reportData) return c.json({ detail: "Investigation not found" }, 404);

  const csv = generateCSVReport(reportData);
  return c.text(csv, 200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": `attachment; filename="shadowtrace-report-${runId}.csv"`,
    "Cache-Control": "private, no-store",
  });
});

// HTML Report Export (Print / PDF)
app.get("/api/v1/search/runs/:run_id/report.html", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) return c.json({ detail: "Investigation not found" }, 404);

  const reportData = await getReportData(c, runId, user);
  if (!reportData) return c.json({ detail: "Investigation not found" }, 404);

  const html = generateHTMLReport(reportData);
  return c.html(html, 200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "private, no-store",
  });
});

// Unmatched routes
app.notFound((c) => {
  return c.json({ detail: "Not Found" }, 404);
});

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => app.fetch(request, env, ctx),
  scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(pruneRateLimits(env.DB));
  },
};
