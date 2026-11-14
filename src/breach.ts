/**
 * Optional Have I Been Pwned k-anonymity range lookup.
 * Only call this for an email address explicitly submitted by the signed-in user.
 * The full SHA-1 digest is never sent to the provider; only its first five hex chars are sent.
 * No breach corpus, passwords, or stolen records are downloaded or stored.
 */
export interface BreachCheckResult {
  checked: boolean;
  provider: "Have I Been Pwned";
  matches: number;
  notice: string;
}

export async function checkEmailBreachExposure(
  email: string,
  apiKey: string,
  fetcher: typeof fetch = fetch
): Promise<BreachCheckResult> {
  const normalized = email.trim().toLowerCase();
  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(normalized) || normalized.length > 254) {
    throw new Error("A valid email address is required");
  }
  if (!apiKey || apiKey.trim().length < 10) throw new Error("Breach-check provider is not configured");
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(normalized));
  const hex = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const response = await fetcher(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "hibp-api-key": apiKey, "Add-Padding": "true", "User-Agent": "ShadowTrace-OSINT" },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error(`Breach provider returned HTTP ${response.status}`);
  const body = await response.text();
  if (body.length > 200_000) throw new Error("Breach provider response exceeded the allowed size");
  const matches = body.split(/\\r?\\n/).some(line => line.split(":")[0]?.trim().toUpperCase() === suffix);
  return {
    checked: true,
    provider: "Have I Been Pwned",
    matches: matches ? 1 : 0,
    notice: "Password-range match is an exposure signal only; it does not identify an account or confirm that this email was breached."
  };
}
