export type SearchType = "username" | "phone" | "email" | "domain";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$/;
const PHONE_RE = /^\+?[0-9][0-9 ()-]{6,22}$/;

export function detectSearchType(value: string): SearchType {
  if (value.includes("@")) return "email";
  if (PHONE_RE.test(value)) return "phone";
  if (DOMAIN_RE.test(value)) return "domain";
  return "username";
}

export function validateSearchInput(value: unknown, requestedType?: unknown): { type: SearchType; value: string } {
  if (typeof value !== "string") throw new Error("Search query must be text");
  const normalized = value.trim();
  if (!normalized || normalized.length > 254 || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("Search query must contain 1–254 printable characters");
  }
  const type = (requestedType || detectSearchType(normalized)) as SearchType;
  if (!["username", "phone", "email", "domain"].includes(type)) throw new Error("Unsupported search type");
  if (type === "email" && (!EMAIL_RE.test(normalized) || normalized.length > 254)) throw new Error("Enter a valid email address");
  if (type === "domain" && !DOMAIN_RE.test(normalized)) throw new Error("Enter a valid public domain name");
  if (type === "phone" && !PHONE_RE.test(normalized)) throw new Error("Enter a valid phone number");
  return { type, value: normalized };
}
