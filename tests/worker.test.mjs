import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  validateUsername,
  PROVIDERS,
  providerCount,
  extractProfileSignals,
  isSoft404Page,
  isAllowedFinalUrl,
} from "../src/providers.ts";
import {
  hashPassword,
  verifyPassword,
  PASSWORD_HASH_ITERATIONS,
  createAccessToken,
  decodeAccessToken,
} from "../src/security.ts";

test("valid username validation", () => {
  assert.equal(validateUsername("octocat_42"), "octocat_42");
  assert.equal(validateUsername("user-name"), "user-name");
  assert.equal(validateUsername("john.doe"), "john.doe");
});

test("invalid username validation throws", () => {
  const invalid = ["", "a", "two words", "../admin", "x".repeat(31), "user?x=1"];
  for (const val of invalid) {
    assert.throws(() => validateUsername(val), /Use 2–30 letters/);
  }
});

test("fixed HTTPS allowlist of providers", () => {
  assert.ok(providerCount() >= 15);
  for (const p of PROVIDERS) {
    assert.ok(p.urlTemplate.startsWith("https://"));
    assert.ok(p.urlTemplate.includes("{username}"));
    assert.ok(p.category.length > 0);
  }
});

test("password hashing and verification round-trip", async () => {
  const pwd = "correct horse battery staple";
  const hashed = await hashPassword(pwd);
  assert.notEqual(hashed, pwd);
  assert.ok(hashed.startsWith("pbkdf2:sha256:"));
  assert.deepEqual(await verifyPassword(pwd, hashed), { ok: true, needsRehash: false });
  assert.deepEqual(await verifyPassword("wrong password", hashed), { ok: false, needsRehash: false });
  assert.match(hashed, new RegExp("^pbkdf2:sha256:" + PASSWORD_HASH_ITERATIONS + "\\$"));
});

test("JWT access token round-trip", async () => {
  const secret = "test-secret-key-at-least-32-chars-long";
  const token = await createAccessToken(42, secret, 60);
  assert.ok(typeof token === "string" && token.length > 10);
  const decoded = await decodeAccessToken(token, secret);
  assert.equal(decoded, 42);

  const invalidToken = await decodeAccessToken("invalid.token.here", secret);
  assert.equal(invalidToken, null);

  const wrongSecret = await decodeAccessToken(token, "different-secret-key-wrong");
  assert.equal(wrongSecret, null);
});


import { detectSearchType, validateSearchInput } from "../src/search.ts";
import { checkPasswordExposure } from "../src/breach.ts";

test("search input type detection and validation", () => {
  assert.equal(detectSearchType("analyst@example.com"), "email");
  assert.equal(detectSearchType("+14155552671"), "phone");
  assert.equal(detectSearchType("example.org"), "domain");
  assert.deepEqual(validateSearchInput("octocat", "username"), { type: "username", value: "octocat" });
  assert.throws(() => validateSearchInput("not-an-email", "email"), /valid email/i);
  assert.throws(() => validateSearchInput("https://example.org", "domain"), /valid public domain/i);
  assert.throws(() => validateSearchInput("x".repeat(255)), /1–254/);
});

test("password exposure lookup sends only the five-character hash prefix", async () => {
  let requested = "";
  const fetcher = async (url, init) => {
    requested = String(url);
    assert.equal(init.headers["Add-Padding"], "true");
    return new Response("", { status: 200 });
  };
  const result = await checkPasswordExposure("a strong test password", fetcher);
  assert.match(requested, /range\/[A-F0-9]{5}$/);
  assert.equal(result.exposed, false);
  assert.equal(result.exposureCount, 0);

  // Test multiline matching when password hash is exposed in range response
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode("exposed-pwd-test"));
  const hex = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const suffix = hex.slice(5);
  const multilineBody = `0018A45C4D63FE8C644FE03513FDCEF729E:1\r\n${suffix}:42\r\n00D4F6E8FA6EEC340B2D3F46E9D33B404D5:2`;
  const hitFetcher = async () => new Response(multilineBody, { status: 200 });
  const hitResult = await checkPasswordExposure("exposed-pwd-test", hitFetcher);
  assert.equal(hitResult.exposed, true);
  assert.equal(hitResult.exposureCount, 42);
});

test("password exposure lookup rejects provider failures", async () => {
  await assert.rejects(
    () => checkPasswordExposure("a strong test password", async () => new Response("", { status: 503 })),
    /HTTP 503/
  );
});

test("legacy PBKDF2 hashes remain valid and request an upgrade", async () => {
  const password = "legacy password test phrase";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const digest = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256
  ));
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  const legacy = "pbkdf2:sha256:100000$" + hex(salt) + "$" + hex(digest);
  assert.deepEqual(await verifyPassword(password, legacy), { ok: true, needsRehash: true });
  assert.deepEqual(await verifyPassword("incorrect password", legacy), { ok: false, needsRehash: false });
});

test("profile metadata extraction yields safe links and display name", () => {
  const html = '<html><head><title>Octo Cat | Codeberg</title><meta property="og:title" content="Octo Cat (@octocat)"><meta property="og:description" content="Developer profile"></head><body><a href="https://github.com/octocat">GitHub</a><a href="javascript:alert(1)">bad</a></body></html>';
  const signals = extractProfileSignals(html, "octocat", "https://codeberg.org/octocat");
  assert.equal(signals.titleMentionsUsername, true);
  assert.match(signals.displayName, /octocat/i);
  assert.equal(signals.links.length, 1);
  assert.equal(new URL(signals.links[0]).hostname, "github.com");
});

test("soft-404 baseline detects generic not-found templates but not distinct profiles", () => {
  const missing = '<html><head><title>Page not found</title></head><body><main>We could not find this page. Please check the address and try again.</main></body></html>';
  const sameMissing = '<html><head><title>Page not found</title></head><body><main>We could not find this page. Please check the address and try again.</main></body></html>';
  const realProfile = '<html><head><title>octocat profile</title></head><body><main>octocat repositories projects followers contributions profile details public account data</main></body></html>';
  const sharedTitleProfile = '<html><head><title>Page not found</title></head><body><main>octocat repositories projects followers contributions profile details public account data and recent activity</main></body></html>';
  assert.equal(isSoft404Page(sameMissing, missing), true);
  assert.equal(isSoft404Page(realProfile, missing), false);
  assert.equal(isSoft404Page(sharedTitleProfile, missing), false);
});


test("provider redirect allowlist rejects cross-brand homepage redirects", () => {
  assert.equal(isAllowedFinalUrl("https://t.me/someuser", "https://t.me/"), true);
  assert.equal(isAllowedFinalUrl("https://steamcommunity.com/id/someuser", "https://steamcommunity.com/"), true);
  assert.equal(isAllowedFinalUrl("https://www.npmjs.com/~someuser", "https://www.npmjs.com/"), true);
  assert.equal(isAllowedFinalUrl("https://t.me/someuser", "https://telegram.org/"), false);
  assert.equal(isAllowedFinalUrl("https://steamcommunity.com/id/someuser", "https://steampowered.com/"), false);
});

import { analyzeEmail } from "../src/email.ts";
import { analyzePhoneNumber } from "../src/phone.ts";
import { analyzeIP } from "../src/ip.ts";
import { analyzeDomain } from "../src/domain.ts";
import { analyzeMetadata } from "../src/metadata.ts";
import { detectCryptoAddress } from "../src/crypto.ts";
import { collectorManager } from "../src/collector.ts";
import { buildKnowledgeGraph } from "../src/graph.ts";
import { generateAISummary } from "../src/ai.ts";
import { generateMarkdownReport, generateCSVReport, generateHTMLReport } from "../src/report.ts";

test("email intelligence distinguishes source observations from account candidates", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    if (url.includes("cloudflare-dns.com/dns-query")) {
      return new Response(JSON.stringify({ Answer: [{ data: "10 mx.example.test." }] }), { status: 200 });
    }
    if (url.includes("keyserver.ubuntu.com")) {
      return new Response('<span class="uid">Fixture Analyst <fixture-alias@example.test></span>', { status: 200 });
    }
    if (url.includes("en.gravatar.com")) {
      return new Response(JSON.stringify({ entry: [] }), { status: 200 });
    }
    if (url.includes("gravatar.com/avatar/")) return new Response("", { status: 404 });
    if (url.includes("api.github.com/search/commits")) {
      return new Response(JSON.stringify({
        items: [{
          commit: { author: { name: "Fixture Commit Author", email: "fixture@example.test", date: "2024-01-02T03:04:05Z" } },
          author: { login: "fixture-author", avatar_url: "https://avatars.githubusercontent.com/u/1" },
          html_url: "https://github.com/fixture/repo/commit/abc123"
        }]
      }), { status: 200 });
    }
    throw new Error("Unexpected provider request: " + url);
  };
  try {
    const result = await analyzeEmail("fixture@example.test");
    assert.equal(result.email, "fixture@example.test");
    assert.equal(result.domain, "example.test");
    assert.equal(result.platforms.find(p => p.name === "DOMAIN MAIL ROUTING (MX)")?.status, "observed");
    assert.equal(result.platforms.find(p => p.name === "GITHUB PUBLIC COMMITS")?.status, "candidate");
    assert.equal(result.platforms.some(p => p.name.includes("HIBP") || p.name === "TWITTER / X"), false);
    assert.deepEqual(result.entities.phones, []);
    assert.ok(result.entities.emails.includes("fixture-alias@example.test"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("phone parsing does not invent carrier, region, messaging accounts, or UPI handles", async () => {
  const result = await analyzePhoneNumber("+12025550123");
  assert.equal(result.e164, "+12025550123");
  assert.equal(result.country, "United States / Canada");
  assert.match(result.carrier, /Unknown/);
  assert.match(result.region, /not a reliable current location/i);
  assert.deepEqual(result.platforms, []);
  assert.deepEqual(result.entities.names, []);
  assert.equal(result.entities.first_seen, undefined);
});

test("metadata extraction reports only supplied content and embedded text", async () => {
  const result = await analyzeMetadata("data:text/plain,fixture%40example.test%20https%3A%2F%2Fexample.test");
  assert.equal(result.kind, "raw");
  assert.equal(result.sha256?.length, 64);
  assert.ok(result.embedded.emails.includes("fixture@example.test"));
  assert.ok(result.embedded.urls.includes("https://example.test"));
  assert.equal("exif" in result, false);
  assert.equal("document" in result, false);
  assert.equal(result.entities.names.length, 0);
});

test("IP intelligence marks provider-returned facts as observations and private ranges skip network calls", async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async input => {
    requests++;
    const url = String(input);
    if (url.startsWith("https://ipwho.is/")) {
      return new Response(JSON.stringify({
        success: true, ip: "1.1.1.1", country: "Australia", country_code: "AU",
        region: "Queensland", city: "South Brisbane", latitude: -27.48, longitude: 153.02,
        timezone: { id: "Australia/Brisbane" },
        connection: { asn: 13335, org: "Cloudflare, Inc.", isp: "Cloudflare" }
      }), { status: 200 });
    }
    if (url.startsWith("https://dns.google/resolve")) {
      return new Response(JSON.stringify({ Answer: [{ data: "one.one.one.one." }] }), { status: 200 });
    }
    if (url.startsWith("https://internetdb.shodan.io/")) {
      return new Response(JSON.stringify({ ip: "1.1.1.1", ports: [80, 443], hostnames: ["one.one.one.one"], vulns: [] }), { status: 200 });
    }
    throw new Error("Unexpected provider request: " + url);
  };
  try {
    const result = await analyzeIP("1.1.1.1");
    assert.equal(result.city, "South Brisbane");
    assert.ok(result.platforms.some(p => p.name === "SHODAN INTERNETDB" && p.status === "observed"));
    assert.ok(result.platforms.every(p => p.status !== "candidate"));
    const before = requests;
    const privateResult = await analyzeIP("192.168.1.10");
    assert.equal(requests, before);
    assert.equal(privateResult.platforms[0].status, "observed");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("domain intelligence includes only live DNS, CT, and RDAP responses", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async input => {
    const url = new URL(String(input));
    if (url.hostname === "cloudflare-dns.com") {
      const type = url.searchParams.get("type");
      const name = url.searchParams.get("name");
      const answers = type === "A" ? [{ data: "203.0.113.10" }]
        : type === "MX" ? [{ data: "10 mail.example.com." }]
        : type === "NS" ? [{ data: "ns1.cloudflare.com." }]
        : type === "TXT" ? (name?.startsWith("_dmarc.") ? [{ data: '"v=DMARC1; p=reject"' }] : [{ data: '"v=spf1 -all"' }])
        : [];
      return new Response(JSON.stringify({ Answer: answers }), { status: 200 });
    }
    if (url.hostname === "crt.sh") {
      return new Response(JSON.stringify([{ name_value: "www.example.com\nmail.example.com" }]), { status: 200 });
    }
    if (url.hostname === "rdap.org") {
      return new Response(JSON.stringify({
        ldhName: "example.com",
        events: [{ eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" }],
        nameservers: [{ ldhName: "ns1.cloudflare.com" }]
      }), { status: 200 });
    }
    throw new Error("Unexpected provider request: " + url.href);
  };
  try {
    const result = await analyzeDomain("example.com");
    assert.deepEqual(result.ipAddresses, ["203.0.113.10"]);
    assert.equal(result.hasSpf, true);
    assert.equal(result.hasDmarc, true);
    assert.equal(result.registeredAt, "2020-01-01T00:00:00Z");
    assert.ok(result.evidence.some(e => e.provider.includes("Certificate Transparency") && e.status === "observed"));
    assert.ok(result.evidence.every(e => e.status !== "candidate"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("crypto address detection describes syntax recognition, not ownership", () => {
  const bitcoin = detectCryptoAddress("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
  assert.equal(bitcoin.blockchain, "Bitcoin");
  assert.equal(bitcoin.isValid, true);
  assert.match(bitcoin.format, /checksum not validated/i);
  const unknown = detectCryptoAddress("not-a-wallet");
  assert.equal(unknown.isValid, false);
});

test("collector manager lists modular plugins without implying provider health", () => {
  const plugins = collectorManager.listPlugins();
  assert.ok(plugins.length >= 7);
  const ids = plugins.map(p => p.id);
  for (const id of ["collector-domain", "collector-ip", "collector-email", "collector-phone", "collector-username", "collector-crypto", "collector-metadata"]) {
    assert.ok(ids.includes(id));
  }
});

test("knowledge graph keeps target and candidate evidence typed", () => {
  const graph = buildKnowledgeGraph("fixture-handle", "username", {
    names: [], emails: ["fixture@example.test"], usernames: ["fixture-handle"]
  }, [{
    provider: "Fixture GitHub",
    category: "identity",
    profile_url: "https://github.com/fixture-handle",
    status: "candidate",
    identifier_display: "@fixture-handle",
    confidence: "medium"
  }]);
  assert.ok(graph.nodes.some(n => n.type === "target"));
  assert.ok(graph.nodes.some(n => n.type === "platform"));
  assert.ok(graph.nodes.some(n => n.type === "email"));
});

test("AI summary never fabricates historical events or identity attribution", () => {
  const ai = generateAISummary("fixture-handle", "username", {
    names: [], emails: ["fixture@example.test"]
  }, [{
    provider: "Fixture GitHub",
    category: "identity",
    status: "candidate",
    confidence: "medium"
  }], {
    overall_threat_score: 0,
    risk_level: "unassessed",
    level: "UNKNOWN"
  });
  assert.equal(ai.threatLevel, "UNKNOWN");
  assert.equal(ai.threatScore, 0);
  assert.equal(ai.timeline.length, 0);
  assert.match(ai.executiveSummary, /does not assert that separate records belong to the same person/i);
  assert.equal(ai.executiveSummary.includes("Primary Identity Attribution"), false);
});

test("reports distinguish candidate leads from technical observations", () => {
  const reportData = {
    id: 999,
    queryType: "username",
    queryValue: "fixture-handle",
    createdAt: new Date().toISOString(),
    entities: { names: [], emails: ["fixture@example.test"] },
    summary: { total: 2, candidates: 1, providers: 2 },
    threatMatrix: { overall_threat_score: 0, risk_level: "unassessed" },
    evidence: [
      {
        provider: "Fixture GitHub",
        category: "identity",
        profile_url: "https://github.com/fixture-handle",
        status: "candidate",
        identifier_display: "@fixture-handle",
        confidence: "medium",
        checked_at: new Date().toISOString()
      },
      {
        provider: "Fixture DNS",
        category: "domain",
        profile_url: "https://example.test",
        status: "observed",
        detail: "A record returned by test fixture",
        checked_at: new Date().toISOString()
      }
    ],
    ai: { executiveSummary: "Fixture evidence summary.", timeline: [], recommendedPivots: [] }
  };
  const markdown = generateMarkdownReport(reportData);
  assert.ok(markdown.includes("Technical Observations"));
  assert.ok(markdown.includes("Fixture DNS"));
  assert.ok(markdown.includes("Unassessed"));
  assert.equal(markdown.includes("Certified deterministic intelligence snapshot"), false);
  const csv = generateCSVReport(reportData);
  assert.ok(csv.includes('"observed"'));
  const html = generateHTMLReport(reportData);
  assert.ok(html.includes("Source-backed Technical Observations"));
  assert.ok(html.includes("Not independently certified"));
});

test("generic profile markers without exact username metadata are not a match", () => {
  const html = '<html><head><title>Welcome to the platform</title><meta property="og:description" content="Followers, posts, profiles and community members"></head><body>followers posts profile</body></html>';
  const signals = extractProfileSignals(html, "fixture-handle", "https://profiles.example.test/fixture-handle");
  assert.equal(signals.titleMentionsUsername, false);
});

test("knowledge graph labels email and phone values as indicators, not recovery channels", () => {
  const graph = buildKnowledgeGraph("fixture-subject", "username", {
    names: [],
    emails: ["alias@example.test"],
    phones: ["+12025550123"],
    usernames: []
  }, []);
  const relationships = graph.edges.map(edge => edge.relationship);
  assert.ok(relationships.includes("email_indicator"));
  assert.ok(relationships.includes("phone_indicator"));
  assert.equal(relationships.includes("recovery_email"), false);
  assert.equal(relationships.includes("recovery_phone"), false);
});


test("HTML username matches require both exact page metadata and exact final profile path", async () => {
  const { profilePathMatchesUsername } = await import("../src/providers.ts");
  assert.equal(profilePathMatchesUsername("https://codeberg.org/octocat", "octocat"), true);
  assert.equal(profilePathMatchesUsername("https://codeberg.org/octocat/", "octocat"), true);
  assert.equal(profilePathMatchesUsername("https://codeberg.org/octocat-fan", "octocat"), false);
  assert.equal(profilePathMatchesUsername("https://codeberg.org/", "octocat"), false);
  assert.equal(profilePathMatchesUsername("https://other.example/octocat", "octocat"), false);
  assert.equal(profilePathMatchesUsername("https://octocat.substack.com", "octocat"), true);
  assert.equal(profilePathMatchesUsername("https://someone-else.substack.com", "octocat"), false);
});


test("OSINT toolbox catalog has honest native-versus-reference availability", async () => {
  const raw = await readFile(new URL("../frontend/osint-tools.json", import.meta.url), "utf8");
  const catalog = JSON.parse(raw);
  assert.equal(catalog.source.name, "Z4nzu/hackingtool");
  assert.equal(catalog.source.license, "MIT");
  assert.ok(catalog.source.commit);
  assert.ok(catalog.tools.length >= 15);
  const native = catalog.tools.filter(tool => tool.status === "integrated");
  const references = catalog.tools.filter(tool => tool.status === "reference");
  assert.ok(native.length >= 7);
  assert.ok(references.length >= 5);
  for (const tool of catalog.tools) {
    assert.ok(tool.id && tool.name && tool.category && tool.description && tool.url);
    assert.ok(["integrated", "reference"].includes(tool.status));
    if (tool.status === "integrated") assert.ok(["username", "email", "phone", "domain", "ip", "crypto", "metadata"].includes(tool.searchType));
    if (tool.status === "reference") assert.equal(tool.searchType, undefined);
  }
});
