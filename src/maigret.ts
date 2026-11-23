/**
 * Maigret OSINT Integration Engine
 * Ported directly from soxoj/maigret (GPL-3.0 / MIT compatible adapter)
 * Features 3,000+ categorized platforms from references/maigret data.json.
 * Collects dossiers on usernames across social, coding, gaming, finance, blogs, and forums.
 */

import fs from "node:fs";
import path from "node:path";
import { validateUsername } from "./providers.ts";

export interface MaigretSite {
  name: string;
  url: string;
  urlMain?: string;
  checkType?: string;
  tags?: string[];
  presenceStrs?: string[];
  absenceStrs?: string[];
}

export interface MaigretResult {
  site: string;
  category: string;
  url: string;
  status: "candidate" | "observed" | "inconclusive" | "not_found";
  confidence: "high" | "medium" | "low" | "none";
  httpStatus: number | null;
  detail: string;
  tags: string[];
  checkedAt: string;
}

let cachedSites: MaigretSite[] | null = null;

function loadMaigretSites(): MaigretSite[] {
  if (cachedSites) return cachedSites;

  const candidatePaths = [
    path.resolve(process.cwd(), "references", "maigret", "maigret", "resources", "data.json"),
    path.resolve(process.cwd(), "references", "maigret", "resources", "data.json"),
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        const raw = JSON.parse(fs.readFileSync(p, "utf8"));
        const sitesObj = raw.sites || raw;
        const list: MaigretSite[] = [];
        for (const [name, info] of Object.entries<any>(sitesObj)) {
          if (info && info.url && typeof info.url === "string") {
            list.push({
              name,
              url: info.url,
              urlMain: info.urlMain,
              checkType: info.checkType,
              tags: Array.isArray(info.tags) ? info.tags : [],
              presenceStrs: info.presenseStrs || info.presenceStrs || [],
              absenceStrs: info.absenceStrs || [],
            });
          }
        }
        cachedSites = list;
        return list;
      } catch (err) {
        console.warn("Notice loading Maigret data.json:", err);
      }
    }
  }

  // Built-in fallback popular sites if references data not yet loaded
  cachedSites = [
    { name: "GitHub", url: "https://github.com/{username}", tags: ["coding", "social"] },
    { name: "GitLab", url: "https://gitlab.com/{username}", tags: ["coding"] },
    { name: "Reddit", url: "https://www.reddit.com/user/{username}", tags: ["social", "forum"] },
    { name: "Medium", url: "https://medium.com/@{username}", tags: ["blog"] },
    { name: "Dev.to", url: "https://dev.to/{username}", tags: ["coding", "blog"] },
    { name: "Telegram", url: "https://t.me/{username}", tags: ["messaging"] },
    { name: "Steam", url: "https://steamcommunity.com/id/{username}", tags: ["gaming"] },
    { name: "HackerNews", url: "https://news.ycombinator.com/user?id={username}", tags: ["news", "tech"] },
    { name: "Spotify", url: "https://open.spotify.com/user/{username}", tags: ["music", "media"] },
    { name: "Keybase", url: "https://keybase.io/{username}", tags: ["crypto", "identity"] },
  ];
  return cachedSites;
}

export async function runMaigretScan(
  username: string,
  options?: { offline?: boolean; limit?: number; tags?: string[]; concurrency?: number }
): Promise<MaigretResult[]> {
  const clean = validateUsername(username);
  const checkedAt = new Date().toISOString();
  const allSites = loadMaigretSites();

  let targetSites = allSites;
  if (options?.tags && options.tags.length > 0) {
    const filterTags = options.tags.map((t) => t.toLowerCase());
    targetSites = targetSites.filter((s) => s.tags?.some((t) => filterTags.includes(t.toLowerCase())));
  }

  const limit = Math.min(targetSites.length, Math.max(1, options?.limit || 50));
  targetSites = targetSites.slice(0, limit);

  if (options?.offline) {
    return targetSites.map((s) => {
      const url = s.url.replace(/\{username\}/g, encodeURIComponent(clean));
      const mainTag = s.tags && s.tags[0] ? s.tags[0] : "social";
      return {
        site: s.name,
        category: mainTag,
        url,
        status: "candidate",
        confidence: "low",
        httpStatus: null,
        detail: `Offline Maigret Recon: Candidate profile URL synthesized (${url}). Live verification skipped in offline mode.`,
        tags: s.tags || [],
        checkedAt,
      };
    });
  }

  // Concurrent probing
  const concurrency = options?.concurrency || 4;
  const results: MaigretResult[] = new Array(targetSites.length);
  let cursor = 0;

  async function worker() {
    while (cursor < targetSites.length) {
      const idx = cursor++;
      const s = targetSites[idx];
      const url = s.url.replace(/\{username\}/g, encodeURIComponent(clean));
      const mainTag = s.tags && s.tags[0] ? s.tags[0] : "social";

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 6000);
        const res = await fetch(url, {
          signal: controller.signal,
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          },
        });
        clearTimeout(timer);

        if (res.status === 200) {
          const body = await res.text();
          let absenceMatched = false;
          if (s.absenceStrs && s.absenceStrs.length > 0) {
            absenceMatched = s.absenceStrs.some((sub) => body.includes(sub));
          }

          if (absenceMatched) {
            results[idx] = {
              site: s.name,
              category: mainTag,
              url,
              status: "not_found",
              confidence: "high",
              httpStatus: 200,
              detail: "Profile not found (matched provider absence marker)",
              tags: s.tags || [],
              checkedAt,
            };
          } else {
            results[idx] = {
              site: s.name,
              category: mainTag,
              url,
              status: "candidate",
              confidence: "medium",
              httpStatus: 200,
              detail: `Candidate profile observed on ${s.name}`,
              tags: s.tags || [],
              checkedAt,
            };
          }
        } else if (res.status === 404) {
          results[idx] = {
            site: s.name,
            category: mainTag,
            url,
            status: "not_found",
            confidence: "high",
            httpStatus: 404,
            detail: "HTTP 404 Not Found",
            tags: s.tags || [],
            checkedAt,
          };
        } else {
          results[idx] = {
            site: s.name,
            category: mainTag,
            url,
            status: "inconclusive",
            confidence: "none",
            httpStatus: res.status,
            detail: `HTTP ${res.status} returned`,
            tags: s.tags || [],
            checkedAt,
          };
        }
      } catch (err: any) {
        results[idx] = {
          site: s.name,
          category: mainTag,
          url,
          status: "inconclusive",
          confidence: "none",
          httpStatus: null,
          detail: err.name === "AbortError" ? "Request timed out" : `Network error: ${err.message}`,
          tags: s.tags || [],
          checkedAt,
        };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, targetSites.length) }, () => worker());
  await Promise.all(workers);
  return results.filter(Boolean);
}
