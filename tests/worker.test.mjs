import test from "node:test";
import assert from "node:assert/strict";
import {
  validateUsername,
  PROVIDERS,
  providerCount,
  extractProfileSignals,
  isSoft404Page,
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
