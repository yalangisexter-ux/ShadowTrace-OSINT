import { sign, verify } from "hono/jwt";

/**
 * Hash password using standard Web Crypto API PBKDF2-SHA256 (100,000 iterations).
 * Zero external native binary dependencies, runs smoothly inside Cloudflare Workers.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const hashHex = Array.from(new Uint8Array(derivedKey))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `pbkdf2:sha256:100000$${saltHex}$${hashHex}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const parts = stored.split("$");
    if (parts.length !== 3) return false;
    const [, saltHex, originalHashHex] = parts;
    const matchBytes = saltHex.match(/.{1,2}/g);
    if (!matchBytes) return false;
    const salt = new Uint8Array(matchBytes.map((byte) => parseInt(byte, 16)));
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const derivedKey = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      256
    );
    const hashHex = Array.from(new Uint8Array(derivedKey))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return hashHex === originalHashHex;
  } catch {
    return false;
  }
}

export async function createAccessToken(
  userId: number,
  secret: string,
  expiresInMinutes: number = 60
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + Math.max(5, expiresInMinutes) * 60;
  const payload = {
    sub: String(userId),
    exp,
  };
  return sign(payload, secret, "HS256");
}

export async function decodeAccessToken(
  token: string,
  secret: string
): Promise<number | null> {
  try {
    const payload = (await verify(token, secret, "HS256")) as { sub?: string; exp?: number };
    if (!payload || !payload.sub) return null;
    const userId = parseInt(payload.sub, 10);
    return isNaN(userId) ? null : userId;
  } catch {
    return null;
  }
}
