import test from "node:test";
import assert from "node:assert/strict";
import {
  validateUsername,
  PROVIDERS,
  providerCount,
} from "../src/providers.ts";
import {
  hashPassword,
  verifyPassword,
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
  assert.equal(await verifyPassword(pwd, hashed), true);
  assert.equal(await verifyPassword("wrong password", hashed), false);
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
