export type SearchType = "username" | "phone" | "email" | "domain" | "ip" | "crypto" | "metadata";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$/;
const PHONE_RE = /^\+?[0-9][0-9 ()-]{6,22}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_RE = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,7}:$/;

// Cryptocurrency patterns
const ETH_RE = /^0x[a-fA-F0-9]{40}$/;
const BTC_RE = /^(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const TRON_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;

export function detectSearchType(value: string): SearchType {
  const clean = value.trim();
  if (clean.startsWith("data:") || clean.match(/\.(jpg|jpeg|png|webp|pdf|docx?)(\?|$)/i)) return "metadata";
  if (clean.includes("@")) return "email";
  if (IPV4_RE.test(clean) || (clean.includes(":") && clean.length <= 45 && IPV6_RE.test(clean))) return "ip";
  if (ETH_RE.test(clean) || BTC_RE.test(clean) || TRON_RE.test(clean)) return "crypto";
  if (PHONE_RE.test(clean)) return "phone";
  if (DOMAIN_RE.test(clean)) return "domain";
  return "username";
}

export function validateSearchInput(value: unknown, requestedType?: unknown): { type: SearchType; value: string } {
  if (typeof value !== "string") throw new Error("Search query must be text");
  const normalized = value.trim();
  if (!normalized || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(normalized)) {
    throw new Error("Search query must contain 1–254 printable characters");
  }
  if (normalized.length > 254 && !normalized.startsWith("data:")) {
    throw new Error("Search query must contain 1–254 printable characters");
  }
  const type = (requestedType || detectSearchType(normalized)) as SearchType;
  const validTypes: SearchType[] = ["username", "phone", "email", "domain", "ip", "crypto", "metadata"];
  if (!validTypes.includes(type)) throw new Error("Unsupported search type");

  if (type === "email" && (!EMAIL_RE.test(normalized) || normalized.length > 254)) throw new Error("Enter a valid email address");
  if (type === "domain" && !DOMAIN_RE.test(normalized)) throw new Error("Enter a valid public domain name");
  if (type === "phone" && !PHONE_RE.test(normalized)) throw new Error("Enter a valid phone number");
  if (type === "ip" && !IPV4_RE.test(normalized) && !IPV6_RE.test(normalized) && !normalized.includes(":")) {
    throw new Error("Enter a valid IPv4 or IPv6 address");
  }
  return { type, value: normalized };
}
