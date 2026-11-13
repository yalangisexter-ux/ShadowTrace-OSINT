import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import {
  providerCount,
  searchUsername,
  validateUsername,
  CheckResult,
} from "./providers";
import { analyzePhoneNumber } from "./phone";
import { analyzeEmail } from "./email";
import { analyzeDomain } from "./domain";
import {
  hashPassword,
  verifyPassword,
  createAccessToken,
  decodeAccessToken,
} from "./security";
import {
  ensureSchema,
  createUser,
  getUserByEmail,
  getUserById,
  createSearchRun,
  listUserRuns,
  getRunDetails,
  UserRow,
} from "./db";

export interface Env {
  DB: D1Database;
  ASSETS?: Fetcher;
  SECRET_KEY?: string;
  APP_ENV?: string;
  ACCESS_TOKEN_MINUTES?: string;
}

const app = new Hono<{ Bindings: Env }>();

// Security headers
app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*"],
      connectSrc: ["'self'", "https://*"],
      frameAncestors: ["'none'"],
    },
    xFrameOptions: "DENY",
    xContentTypeOptions: "nosniff",
    referrerPolicy: "strict-origin-when-cross-origin",
  })
);

// Global CORS allowlist
app.use(
  "/api/*",
  cors({
    origin: (origin) => {
      if (!origin) return "*";
      if (
        origin.endsWith(".workers.dev") ||
        origin.endsWith(".pages.dev") ||
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

// In-memory rate limiting bucket
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function throttle(key: string, limit: number, windowSeconds: number): void {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
    return;
  }
  if (bucket.count >= limit) {
    const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
    throw new Error(`Rate limit exceeded. Try again in ${retryAfter}s`);
  }
  bucket.count++;
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

// Root route: serve frontend with strict no-cache headers to prevent stale browser cache
app.get("/", async (c) => {
  if (c.env.ASSETS) {
    const res = await c.env.ASSETS.fetch(c.req.raw);
    const newHeaders = new Headers(res.headers);
    newHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
    newHeaders.set("Pragma", "no-cache");
    newHeaders.set("Expires", "0");
    return new Response(res.body, {
      status: res.status,
      headers: newHeaders,
    });
  }
  return c.text("ShadowTrace OSINT", 200);
});

// Helper: resolve secret key
const DEFAULT_FALLBACK_SECRET = "st_live_cf_89f02e64a138bb92c7104d538e11a2f90b";
function getSecretKey(env: Env): string {
  return env.SECRET_KEY || DEFAULT_FALLBACK_SECRET;
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

// Calculate Digital Threat & Attack Surface Score
function calculateThreatMatrix(results: CheckResult[], queryType: string) {
  const candidates = results.filter((r) => r.status === "candidate");
  const candidateCount = candidates.length;

  let baseScore = 0;
  if (queryType === "phone") {
    baseScore = Math.min(95, 30 + candidateCount * 10);
  } else if (queryType === "email") {
    baseScore = Math.min(90, 25 + candidateCount * 11);
  } else if (queryType === "domain") {
    const hasSpfIssue = results.some((r) => r.detail.includes("MISSING"));
    baseScore = hasSpfIssue ? 65 : 20;
  } else {
    baseScore = Math.min(95, candidateCount * 12);
  }

  let threatLevel: "LOW" | "MODERATE" | "ELEVATED" | "HIGH" | "CRITICAL" = "LOW";
  if (baseScore >= 75) threatLevel = "CRITICAL";
  else if (baseScore >= 55) threatLevel = "HIGH";
  else if (baseScore >= 35) threatLevel = "ELEVATED";
  else if (baseScore >= 15) threatLevel = "MODERATE";

  return {
    score: baseScore,
    level: threatLevel,
    exposure_summary: `${candidateCount} public identity anchors indexed`,
    credential_reuse_risk: candidateCount > 2 ? "High (Multiple identical platform handles)" : "Low / Isolated",
    phishing_surface: queryType === "email" || queryType === "phone" ? "High (Direct communication vector)" : "Moderate",
  };
}

// Health check endpoint
app.get("/healthz", async (c) => {
  const secretKey = getSecretKey(c.env);
  const secretOk = secretKey.length >= 32;
  const dbOk = Boolean(c.env.DB);
  const status = secretOk && dbOk ? "ok" : "degraded";

  return c.json({
    status,
    service: "shadowtrace-osint",
    version: "0.3.0-cloudflare",
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

// Search: Multi-Modal OSINT Investigation (Username, Phone, Email, Domain)
app.post("/api/v1/search/username", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  const rawQuery = String(body.username || body.query || "").trim();
  let searchType = body.type;

  // Auto-detect type if not explicitly supplied
  if (!searchType) {
    if (rawQuery.includes("@")) {
      searchType = "email";
    } else if (/^\+?\d{8,15}$/.test(rawQuery.replace(/[\s-]/g, ""))) {
      searchType = "phone";
    } else if (/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(rawQuery)) {
      searchType = "domain";
    } else {
      searchType = "username";
    }
  }

  // Check if authenticated
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
  try {
    if (user) {
      throttle(`search:user:${user.id}`, 15, 60);
    } else {
      throttle(`search:guest:${clientIp}`, 20, 60);
    }
  } catch (err: any) {
    return c.json({ detail: err.message }, 429);
  }

  let results: CheckResult[] = [];
  let queryLabel = rawQuery;
  let entities: any = {
    names: [],
    profile_pictures: [],
    banners: [],
    usernames: [],
    emails: [],
    phones: [],
    first_seen: undefined,
    last_seen: undefined,
  };

  // 1. Phone Intelligence
  if (searchType === "phone") {
    const phoneData = analyzePhoneNumber(rawQuery);
    queryLabel = phoneData.formatted;
    entities = phoneData.entities;

    for (const p of phoneData.platforms) {
      results.push({
        provider: p.name,
        category: p.category.toLowerCase().includes("messag") ? "social" : (p.category.toLowerCase().includes("finan") ? "identity" : "identity"),
        profile_url: p.url,
        domain: p.icon,
        status: p.status === "verified" ? "candidate" : p.status,
        http_status: 200,
        confidence: "high",
        identity_name: p.identityName,
        identifier_display: `Phone: ${phoneData.formatted}`,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      });
    }

    results.push({
      provider: `${phoneData.country} Telecom Authority`,
      category: "identity",
      profile_url: `tel:${phoneData.e164}`,
      domain: "itu.int",
      status: "candidate",
      http_status: 200,
      confidence: "high",
      identifier_display: `E.164: ${phoneData.e164}`,
      fields_count: 4,
      extra_fields: {
        "E.164 Standard": phoneData.e164,
        "Carrier Allocation": phoneData.carrier,
        "Circle / Region": phoneData.region,
        "Line Type": phoneData.lineType,
        "Timezone": phoneData.timezone
      },
      detail: `E.164: ${phoneData.e164} · Carrier: ${phoneData.carrier} · Circle/Region: ${phoneData.region} · Type: ${phoneData.lineType} · TZ: ${phoneData.timezone}`,
      checked_at: new Date().toISOString(),
    });
  }
  // 2. Email Intelligence
  else if (searchType === "email") {
    const emailData = await analyzeEmail(rawQuery);
    queryLabel = emailData.email;
    entities = emailData.entities;

    for (const p of emailData.platforms) {
      results.push({
        provider: p.name,
        category: p.category.toLowerCase().includes("code") ? "code" : (p.category.toLowerCase().includes("messag") || p.category.toLowerCase().includes("social") ? "social" : "identity"),
        profile_url: p.url,
        domain: p.icon,
        status: p.status === "verified" ? "candidate" : p.status,
        http_status: 200,
        confidence: "high",
        identity_name: p.identityName,
        identifier_display: p.identifierDisplay || `Email: ${emailData.email}`,
        fields_count: p.fieldsCount || 1,
        extra_fields: p.extraFields,
        detail: p.detail,
        checked_at: new Date().toISOString(),
      });
    }

    results.push({
      provider: `Mail Provider (${emailData.provider})`,
      category: "identity",
      profile_url: `https://${emailData.domain}`,
      domain: emailData.domain,
      status: "candidate",
      http_status: 200,
      confidence: "high",
      identifier_display: `@${emailData.domain}`,
      fields_count: 3,
      extra_fields: {
        "Mail Domain": emailData.domain,
        "Service Type": emailData.isFreeProvider ? "Public Consumer Webmail" : "Enterprise / Private Exchange",
        "Burner Risk": emailData.isDisposable ? "HIGH (Disposable Domain)" : "Clean"
      },
      detail: `Active Mail Domain: @${emailData.domain}. Type: ${emailData.isFreeProvider ? "Free Public Webmail" : "Enterprise / Private Domain"}. Handle: ${emailData.username}`,
      checked_at: new Date().toISOString(),
    });
  }
  // 3. Domain & Infrastructure OSINT
  else if (searchType === "domain") {
    const domainData = await analyzeDomain(rawQuery);
    queryLabel = domainData.domain;
    entities = {
      names: [domainData.domain],
      profile_pictures: [`https://www.google.com/s2/favicons?domain=${encodeURIComponent(domainData.domain)}&sz=64`],
      banners: [],
      usernames: [],
      emails: domainData.mailServers.slice(0, 2),
      phones: [],
      first_seen: "Cloudflare Edge",
    };
    results = domainData.evidence.map((e) => ({
      provider: e.provider,
      category: e.category,
      profile_url: e.profile_url,
      domain: e.domain,
      status: e.status,
      http_status: e.http_status,
      confidence: e.confidence,
      detail: e.detail,
      checked_at: e.checked_at,
    }));
  }
  // 4. Username Intelligence across 34+ Sources
  else {
    let username: string;
    try {
      username = validateUsername(rawQuery);
    } catch (err: any) {
      return c.json({ detail: err.message }, 422);
    }
    queryLabel = username;
    const depth = parseInt(body.depth || "0", 10) || 0;
    results = await searchUsername(username, depth);
    entities = {
      names: [username],
      profile_pictures: [`https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(username)}`],
      banners: [],
      usernames: [username],
      emails: [],
      phones: [],
      first_seen: "Public Registry",
    };
  }

  const candidates = results.filter((r) => r.status === "candidate").length;
  const threatMatrix = calculateThreatMatrix(results, searchType);
  let runId = Date.now();
  let createdAt = new Date().toISOString();

  // If authenticated and DB available, persist run
  if (user && c.env.DB) {
    const { run } = await createSearchRun(c.env.DB, user.id, queryLabel, results);
    runId = run.id;
    createdAt = run.created_at;
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
  const authHeader = c.req.header("Authorization");
  const queryToken = c.req.query("token");
  const token = queryToken || (authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null);

  const runId = parseInt(c.req.param("run_id"), 10);
  if (isNaN(runId)) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  let data: any = null;
  if (token) {
    const secret = getSecretKey(c.env);
    const userId = await decodeAccessToken(token, secret);
    if (userId) {
      data = await getRunDetails(c.env.DB, runId, userId);
    }
  }

  if (!data && c.env.DB) {
    const run = await c.env.DB.prepare("SELECT * FROM search_runs WHERE id = ? LIMIT 1").bind(runId).first<any>();
    if (run) {
      const { results: evidence } = await c.env.DB.prepare("SELECT * FROM evidence WHERE run_id = ? ORDER BY id ASC").bind(runId).all<any>();
      data = { run, evidence: evidence || [] };
    }
  }

  if (!data) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const lines = [
    `# ShadowTrace Executive OSINT Intelligence Report`,
    ``,
    `**Target Query:** \`${data.run.query_value}\` (${data.run.query_type})`,
    `**Investigation Run ID:** #${data.run.id}`,
    `**Generated At:** ${data.run.created_at}`,
    ``,
    `## Evidence & Digital Footprint Findings`,
    ``,
  ];

  const sortedEvidence = [...data.evidence].sort((a, b) => {
    const aIsCand = a.status === "candidate" ? 0 : 1;
    const bIsCand = b.status === "candidate" ? 0 : 1;
    if (aIsCand !== bIsCand) return aIsCand - bIsCand;
    return a.provider.localeCompare(b.provider);
  });

  for (const e of sortedEvidence) {
    lines.push(`### ${e.provider} [${e.category.toUpperCase()}]`);
    lines.push(`- Status: **${e.status.toUpperCase()}** (Confidence: ${e.confidence})`);
    lines.push(`- Direct URL: ${e.profile_url}`);
    lines.push(`- HTTP Response: ${e.http_status ?? "—"}`);
    lines.push(`- Intelligence: ${e.detail}`);
    lines.push(`- Timestamp: ${e.checked_at}`);
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(`Candidate records are derived from public OSINT telemetry. Manually verify identity ownership before acting on evidence.`);
  lines.push(`Generated by ShadowTrace OSINT Engine on Cloudflare Workers.`);

  return c.text(lines.join("\n"), 200, {
    "Content-Type": "text/markdown; charset=utf-8",
  });
});

// Unmatched routes
app.notFound((c) => {
  return c.json({ detail: "Not Found" }, 404);
});

export default app;
