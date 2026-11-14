import { sign, verify } from "hono/jwt";

export const PASSWORD_HASH_ITERATIONS = 310000;
const MIN_ACCEPTED_ITERATIONS = 10000;
const MAX_ACCEPTED_ITERATIONS = 2000000;
const HEX_32 = /^[0-9a-f]{32}$/i;
const HEX_64 = /^[0-9a-f]{64}$/i;

export interface PasswordVerification {
  ok: boolean;
  needsRehash: boolean;
}

/** PBKDF2-SHA256 password hashing using the Workers Web Crypto API. */
export async function hashPassword(password: string): Promise<string> {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new Error("Password must be between 12 and 128 characters long");
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_HASH_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const toHex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  return "pbkdf2:sha256:" + PASSWORD_HASH_ITERATIONS + "$" + toHex(salt) + "$" + toHex(new Uint8Array(derived));
}

/** Verifies legacy/current PBKDF2 hashes and signals whether a successful login should upgrade them. */
export async function verifyPassword(password: string, stored: string): Promise<PasswordVerification> {
  try {
    if (typeof password !== "string" || password.length > 128 || typeof stored !== "string") {
      return { ok: false, needsRehash: false };
    }
    const match = /^pbkdf2:sha256:(\d+)\$([0-9a-f]{32})\$([0-9a-f]{64})$/i.exec(stored);
    if (!match) return { ok: false, needsRehash: false };

    const iterations = Number(match[1]);
    if (!Number.isSafeInteger(iterations) || iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
      return { ok: false, needsRehash: false };
    }

    const saltHex = match[2];
    const expectedHex = match[3];
    const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(byte => Number.parseInt(byte, 16)));
    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const derived = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      256
    ));
    let difference = 0;
    for (let i = 0; i < derived.length; i++) {
      difference |= derived[i] ^ Number.parseInt(expectedHex.slice(i * 2, i * 2 + 2), 16);
    }
    const ok = difference === 0;
    return { ok, needsRehash: ok && iterations < PASSWORD_HASH_ITERATIONS };
  } catch {
    return { ok: false, needsRehash: false };
  }
}

export async function createAccessToken(
  userId: number,
  secret: string,
  expiresInMinutes = 60
): Promise<string> {
  if (!Number.isSafeInteger(userId) || userId <= 0) throw new Error("Invalid user identifier");
  if (typeof secret !== "string" || secret.length < 32) throw new Error("Authentication secret must contain at least 32 characters");
  const minutes = Number.isFinite(expiresInMinutes) ? Math.min(1440, Math.max(5, expiresInMinutes)) : 60;
  const payload = { sub: String(userId), exp: Math.floor(Date.now() / 1000) + Math.floor(minutes) * 60 };
  return sign(payload, secret, "HS256");
}

export async function decodeAccessToken(token: string, secret: string): Promise<number | null> {
  try {
    if (typeof token !== "string" || token.length > 4096 || typeof secret !== "string" || secret.length < 32) return null;
    const payload = (await verify(token, secret, "HS256")) as { sub?: string; exp?: number };
    if (!payload || typeof payload.sub !== "string" || !/^[1-9]\d*$/.test(payload.sub)) return null;
    const userId = Number(payload.sub);
    return Number.isSafeInteger(userId) && userId > 0 ? userId : null;
  } catch {
    return null;
  }
}
