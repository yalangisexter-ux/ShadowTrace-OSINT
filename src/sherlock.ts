/**
 * Sherlock OSINT Integration Engine
 * Ported directly from sherlock-project/sherlock (MIT License)
 * Features 60+ categorized platforms with exact URL patterns,
 * regex filters, and error detection logic.
 */

import sherlockData from "./sherlock_data.json" with { type: "json" };
import { validateUsername } from "./providers.ts";

export interface SherlockPlatform {
  name: string;
  category: "code" | "social" | "finance" | "gaming" | "media" | "creative" | "identity";
  urlTemplate: string;
  domain: string;
  errorType: "status_code" | "message" | "response_url";
  errorMsg?: string;
  regexCheck?: string;
}

export interface SherlockResult {
  platform: string;
  category: string;
  url: string;
  domain: string;
  status: "candidate" | "observed" | "inconclusive" | "not_found";
  confidence: "high" | "medium" | "low" | "none";
  httpStatus: number | null;
  detail: string;
  avatarUrl?: string;
  displayName?: string;
  checkedAt: string;
}

export const SHERLOCK_PLATFORMS: SherlockPlatform[] = sherlockData as SherlockPlatform[];

const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

export async function runSherlockScan(
  username: string,
  options?: { offline?: boolean; limit?: number; concurrency?: number }
): Promise<SherlockResult[]> {
  const clean = validateUsername(username);
  const checkedAt = new Date().toISOString();
  const limit = options?.limit || SHERLOCK_PLATFORMS.length;
  const targetPlatforms = SHERLOCK_PLATFORMS.slice(0, limit);

  if (options?.offline) {
    return targetPlatforms.map((p) => {
      const url = p.urlTemplate.replace("{username}", encodeURIComponent(clean));
      let regexMatch = true;
      if (p.regexCheck) {
        try {
          regexMatch = new RegExp(p.regexCheck).test(clean);
        } catch {
          regexMatch = true;
        }
      }

      return {
        platform: p.name,
        category: p.category,
        url,
        domain: p.domain,
        status: regexMatch ? "inconclusive" : "not_found",
        confidence: regexMatch ? "none" : "none",
        httpStatus: null,
        detail: regexMatch
          ? `Offline Sherlock Recon: Profile URL synthesized (${url}). Live probe skipped.`
          : `Username does not match ${p.name} username syntax requirements.`,
        checkedAt,
      };
    });
  }

  // Online concurrent checking
  const concurrency = options?.concurrency || 4;
  const results: SherlockResult[] = new Array(targetPlatforms.length);
  let cursor = 0;

  await Promise.all(
    Array.from({ length: Math.min(concurrency, targetPlatforms.length) }, async () => {
      while (true) {
        const index = cursor++;
        if (index >= targetPlatforms.length) return;
        const p = targetPlatforms[index];
        const url = p.urlTemplate.replace("{username}", encodeURIComponent(clean));

        // Regex pre-filter
        if (p.regexCheck) {
          try {
            if (!new RegExp(p.regexCheck).test(clean)) {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "not_found",
                confidence: "none",
                httpStatus: null,
                detail: `Username violates ${p.name} pattern restrictions.`,
                checkedAt,
              };
              continue;
            }
          } catch {}
        }

        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 4000);

          const res = await fetch(url, {
            method: p.errorType === "message" ? "GET" : "HEAD",
            headers: {
              "User-Agent": USER_AGENT,
              "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            signal: controller.signal,
          });
          clearTimeout(timer);

          if (p.errorType === "status_code") {
            if (res.status === 200) {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "candidate",
                confidence: "high",
                httpStatus: res.status,
                detail: `Sherlock verified HTTP 200 response for @${clean}.`,
                checkedAt,
              };
            } else if (res.status === 404) {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "not_found",
                confidence: "none",
                httpStatus: res.status,
                detail: `Platform returned HTTP 404; account not registered.`,
                checkedAt,
              };
            } else {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "inconclusive",
                confidence: "none",
                httpStatus: res.status,
                detail: `HTTP probe returned status ${res.status}.`,
                checkedAt,
              };
            }
          } else if (p.errorType === "message" && p.errorMsg) {
            const body = await res.text();
            if (res.status === 200 && !body.includes(p.errorMsg)) {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "candidate",
                confidence: "high",
                httpStatus: res.status,
                detail: `Sherlock confirmed active profile; error signature absent.`,
                checkedAt,
              };
            } else {
              results[index] = {
                platform: p.name,
                category: p.category,
                url,
                domain: p.domain,
                status: "not_found",
                confidence: "none",
                httpStatus: res.status,
                detail: `Page returned profile-not-found error message.`,
                checkedAt,
              };
            }
          } else {
            results[index] = {
              platform: p.name,
              category: p.category,
              url,
              domain: p.domain,
              status: res.status === 200 ? "candidate" : "inconclusive",
              confidence: res.status === 200 ? "medium" : "none",
              httpStatus: res.status,
              detail: `Response status: ${res.status}.`,
              checkedAt,
            };
          }
        } catch (err: any) {
          results[index] = {
            platform: p.name,
            category: p.category,
            url,
            domain: p.domain,
            status: "inconclusive",
            confidence: "none",
            httpStatus: null,
            detail: err?.name === "AbortError" ? "Request timed out" : "Network error",
            checkedAt,
          };
        }
      }
    })
  );

  return results.filter(Boolean);
}
