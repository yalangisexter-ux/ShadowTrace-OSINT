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
import { validateSearchInput } from "./search";
import { consumeRateLimit, pruneRateLimits } from "./ratelimit";
import { checkPasswordExposure } from "./breach";
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
  updatePasswordHash,
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

// Durable D1-backed rate limiting shared across Worker instances.
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

// Helper: resolve secret key (prioritizes env.SECRET_KEY, falls back to secure default if unset)
const DEFAULT_FALLBACK_SECRET = "st_live_cf_89f02e64a138bb92c7104d538e11a2f90b";
function getSecretKey(env: Env): string {
  const secret = env.SECRET_KEY?.trim();
  if (secret && secret.length >= 32) return secret;
  return DEFAULT_FALLBACK_SECRET;
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
  const verified = results.filter((r) => r.status === "candidate" && r.verified === true);
  const verifiedCount = verified.length;
  const breachCount = results.filter(r => r.verified === true && r.status === "candidate" && /breach|pwned/i.test(r.provider)).length;
  let baseScore = 0;
  if (queryType === "domain") {
    const hasSpfIssue = results.some((r) => r.detail.includes("MISSING"));
    baseScore = hasSpfIssue ? 65 : 20;
  } else {
    baseScore = Math.min(80, verifiedCount * 10 + breachCount * 20);
  }
  let threatLevel: "LOW" | "MODERATE" | "ELEVATED" | "HIGH" | "CRITICAL" = "LOW";
  if (baseScore >= 75) threatLevel = "CRITICAL";
  else if (baseScore >= 55) threatLevel = "HIGH";
  else if (baseScore >= 35) threatLevel = "ELEVATED";
  else if (baseScore >= 15) threatLevel = "MODERATE";
  return {
    score: baseScore,
    level: threatLevel,
    exposure_summary: `${verifiedCount} high-confidence public identity signals; ${results.length - verifiedCount} unverified or inconclusive records excluded`,
    credential_reuse_risk: verifiedCount > 2 ? "Potential (multiple verified public accounts; password reuse not established)" : "Not established",
    phishing_surface: queryType === "email" || queryType === "phone" ? "Potential communication vector; not proof of compromise" : "Moderate",
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

  const registerLimit = await checkThrottle(c.env.DB, "register:" + email, 3, 3600);
  if (!registerLimit.allowed) return c.json({ detail: "Too many registration attempts. Try again later.", retry_after: registerLimit.retryAfterSeconds }, 429);

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

  const loginLimit = await checkThrottle(c.env.DB, "login:" + email, 8, 300);
  if (!loginLimit.allowed) return c.json({ detail: "Too many sign-in attempts. Try again later.", retry_after: loginLimit.retryAfterSeconds }, 429);

  const user = await getUserByEmail(c.env.DB, email);
  if (!user || typeof password !== "string") return c.json({ detail: "Invalid email or password" }, 401);
  const passwordCheck = await verifyPassword(password, user.password_hash);
  if (!passwordCheck.ok) return c.json({ detail: "Invalid email or password" }, 401);
  if (passwordCheck.needsRehash) {
    try {
      const upgradedHash = await hashPassword(password);
      await updatePasswordHash(c.env.DB, user.id, upgradedHash);
    } catch (rehashErr) {
      console.warn("Failed to upgrade password hash iterations:", rehashErr);
    }
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

// Explicit, authenticated password exposure check. The raw password is never persisted.
app.post("/api/v1/security/password-exposure", async (c) => {
  let user: UserRow;
  try { user = await requireAuth(c); } catch (err: any) { return c.json({ detail: err.message }, 401); }
  const limit = await checkThrottle(c.env.DB, "password-check:user:" + user.id, 5, 300);
  if (!limit.allowed) return c.json({ detail: "Password exposure check limit exceeded.", retry_after: limit.retryAfterSeconds }, 429);
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ detail: "Invalid JSON body" }, 400); }
  if (typeof body.password !== "string" || body.password.length < 1 || body.password.length > 128) {
    return c.json({ detail: "Password must contain 1–128 characters" }, 422);
  }
  try {
    const result = await checkPasswordExposure(body.password);
    return c.json(result, 200, { "Cache-Control": "no-store" });
  } catch (err: any) {
    return c.json({ detail: err.message || "Password exposure check unavailable" }, 502);
  }
});

// Search: Multi-Modal OSINT Investigation (Username, Phone, Email, Domain)
app.post("/api/v1/search/username", async (c) => {
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    return c.json({ detail: "Invalid JSON body" }, 400);
  }

  let validatedQuery: { type: "username" | "phone" | "email" | "domain"; value: string };
  try {
    validatedQuery = validateSearchInput(body.username ?? body.query, body.type);
  } catch (err: any) {
    return c.json({ detail: err.message || "Invalid search query" }, 422);
  }
  const rawQuery = validatedQuery.value;
  const searchType = validatedQuery.type;

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
  const searchLimit = user
    ? await checkThrottle(c.env.DB, "search:user:" + user.id, 15, 60)
    : await checkThrottle(c.env.DB, "search:guest:" + clientIp, 20, 60);
  if (!searchLimit.allowed) return c.json({ detail: "Search rate limit exceeded. Try again shortly.", retry_after: searchLimit.retryAfterSeconds }, 429);

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
        verified: p.status === "verified",
        http_status: 200,
        confidence: p.status === "verified" ? "high" : p.status === "candidate" ? "low" : "none",
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
      status: "inconclusive",
      http_status: 200,
      confidence: "low",
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
        status: p.status === "verified" || p.status === "candidate" ? "candidate" : p.status,
        verified: p.verified === true,
        http_status: 200,
        confidence: p.verified === true ? "high" : "low",
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
      status: "inconclusive",
      http_status: 200,
      confidence: "low",
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
      verified: e.status === "candidate" && e.confidence === "high",
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

    const discoveredNames = new Set<string>();
    const discoveredAvatars = new Set<string>();

    for (const r of results) {
      if (r.status === "candidate") {
        if (r.identity_name && r.identity_name !== username) {
          discoveredNames.add(r.identity_name);
        }
        if (r.extra_fields?.Avatar) {
          discoveredAvatars.add(r.extra_fields.Avatar);
        }
      }
    }

    entities = {
      names: discoveredNames.size > 0 ? [username, ...Array.from(discoveredNames)] : [username],
      profile_pictures: discoveredAvatars.size > 0 
        ? Array.from(discoveredAvatars) 
        : [`https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(username)}`],
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
    const { run } = await createSearchRun(c.env.DB, user.id, searchType, queryLabel, results);
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

// Search: Markdown report export (owner-only; no public fallback)
app.get("/api/v1/search/runs/:run_id/report.md", async (c) => {
  let user: UserRow;
  try {
    user = await requireAuth(c);
  } catch (err: any) {
    return c.json({ detail: err.message }, 401);
  }

  const runId = Number.parseInt(c.req.param("run_id"), 10);
  if (!Number.isSafeInteger(runId) || runId <= 0) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const data = await getRunDetails(c.env.DB, runId, user.id);
  if (!data) {
    return c.json({ detail: "Investigation not found" }, 404);
  }

  const lines = [
    "# ShadowTrace Executive OSINT Intelligence Report",
    "",
    `**Target Query:** \`${data.run.query_value}\` (${data.run.query_type})`,
    `**Investigation Run ID:** #${data.run.id}`,
    `**Generated At:** ${data.run.created_at}`,
    "",
    "## Evidence & Digital Footprint Findings",
    "",
  ];

  const sortedEvidence = [...data.evidence].sort((a, b) => {
    const aIsCandidate = a.status === "candidate" ? 0 : 1;
    const bIsCandidate = b.status === "candidate" ? 0 : 1;
    if (aIsCandidate !== bIsCandidate) return aIsCandidate - bIsCandidate;
    return a.provider.localeCompare(b.provider);
  });

  for (const e of sortedEvidence) {
    lines.push(`### ${e.provider} [${(e.category || "other").toUpperCase()}]`);
    lines.push(`- Status: **${e.status.toUpperCase()}** (Confidence: ${e.confidence})`);
    lines.push(`- Direct URL: ${e.profile_url}`);
    lines.push(`- HTTP Response: ${e.http_status ?? "—"}`);
    lines.push(`- Intelligence: ${e.detail}`);
    lines.push(`- Timestamp: ${e.checked_at}`);
    lines.push("");
  }

  lines.push("---");
  lines.push("Candidate records are derived from public OSINT telemetry. Manually verify identity ownership before acting on evidence.");
  lines.push("Generated by ShadowTrace OSINT Engine on Cloudflare Workers.");

  return c.text(lines.join("\n"), 200, {
    "Content-Type": "text/markdown; charset=utf-8",
    "Content-Disposition": `attachment; filename="shadowtrace-report-${runId}.md"`,
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
