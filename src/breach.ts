/**
 * Privacy-preserving Pwned Passwords range check.
 * The password itself is never sent: only the first five SHA-1 hex characters
 * are sent to the range API. Do not log or persist the supplied password.
 */
export interface PasswordExposureResult {
  checked: true;
  provider: "Have I Been Pwned Pwned Passwords";
  exposureCount: number;
  exposed: boolean;
  notice: string;
}

export async function checkPasswordExposure(
  password: string,
  fetcher: typeof fetch = fetch
): Promise<PasswordExposureResult> {
  if (typeof password !== "string" || password.length < 1 || password.length > 128) {
    throw new Error("Password must contain 1–128 characters");
  }
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
  const hex = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const response = await fetcher(`https://api.pwnedpasswords.com/range/${hex.slice(0, 5)}`, {
    headers: { "Add-Padding": "true", "User-Agent": "ShadowTrace-OSINT" },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error(`Breach provider returned HTTP ${response.status}`);
  const body = await response.text();
  if (body.length > 200_000) throw new Error("Breach provider response exceeded the allowed size");
  const line = body.split(/\r?\n/).find(item => item.split(":")[0]?.trim().toUpperCase() === hex.slice(5));
  const exposureCount = line ? Number.parseInt(line.split(":")[1] || "0", 10) : 0;
  return {
    checked: true,
    provider: "Have I Been Pwned Pwned Passwords",
    exposureCount: Number.isFinite(exposureCount) ? exposureCount : 0,
    exposed: exposureCount > 0,
    notice: "Only a partial SHA-1 hash prefix was sent. This checks password exposure, not whether an email account was breached. Never reuse an exposed password."
  };
}
