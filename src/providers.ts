/**
 * Curated allowlist of public profile sources.
 * Never accepts arbitrary URLs.
 */

export interface Provider {
  name: string;
  urlTemplate: string;
  notFoundMarkers: string[];
  existsMarkers: string[];
  category: "code" | "social" | "creative" | "writing" | "identity";
  domain: string;
}

export interface CheckResult {
  provider: string;
  category: string;
  profile_url: string;
  domain: string;
  status: "candidate" | "not_found" | "inconclusive";
  http_status: number | null;
  confidence: "none" | "low" | "medium" | "high";
  detail: string;
  checked_at: string;
}

export const PROVIDERS: Provider[] = [
  {
    name: "GitHub",
    urlTemplate: "https://github.com/{username}",
    notFoundMarkers: ["<title>page not found", "this is not the web page you are looking for"],
    existsMarkers: ["followers", "repositories", "joined", "pinned", "overview"],
    category: "code",
    domain: "github.com",
  },
  {
    name: "GitLab",
    urlTemplate: "https://gitlab.com/{username}",
    notFoundMarkers: ["<title>the page you're looking for can't be found", "the page you are looking for doesn't exist", "users/sign_in"],
    existsMarkers: ["user-profile", "activity", "personal projects"],
    category: "code",
    domain: "gitlab.com",
  },
  {
    name: "Codeberg",
    urlTemplate: "https://codeberg.org/{username}",
    notFoundMarkers: ["<title>page not found", "<title>404"],
    existsMarkers: ["user profile", "repositories"],
    category: "code",
    domain: "codeberg.org",
  },
  {
    name: "Bitbucket",
    urlTemplate: "https://bitbucket.org/{username}/",
    notFoundMarkers: ["page not found", "repository not found", "resource not found"],
    existsMarkers: ["overview", "repositories"],
    category: "code",
    domain: "bitbucket.org",
  },
  {
    name: "SourceHut",
    urlTemplate: "https://sr.ht/~{username}",
    notFoundMarkers: ["page not found", "no such user"],
    existsMarkers: ["repositories", "pgp key"],
    category: "code",
    domain: "sr.ht",
  },
  {
    name: "DEV Community",
    urlTemplate: "https://dev.to/{username}",
    notFoundMarkers: ["<title>page not found", "this page does not exist"],
    existsMarkers: ["articles written", "following", "joined on"],
    category: "code",
    domain: "dev.to",
  },
  {
    name: "Hashnode",
    urlTemplate: "https://hashnode.com/@{username}",
    notFoundMarkers: ["page not found", "user not found", "could not find"],
    existsMarkers: ["joined", "articles", "badges"],
    category: "code",
    domain: "hashnode.com",
  },
  {
    name: "Replit",
    urlTemplate: "https://replit.com/@{username}",
    notFoundMarkers: ["page not found", "user not found", "404 not found"],
    existsMarkers: ["repls", "cycles"],
    category: "code",
    domain: "replit.com",
  },
  {
    name: "Glitch",
    urlTemplate: "https://glitch.com/@{username}",
    notFoundMarkers: ["page not found", "we couldn't find"],
    existsMarkers: ["glitch apps", "view profile"],
    category: "code",
    domain: "glitch.com",
  },
  {
    name: "CodePen",
    urlTemplate: "https://codepen.io/{username}",
    notFoundMarkers: ["404: page not found", "pen not found"],
    existsMarkers: ["pens", "followers", "following"],
    category: "code",
    domain: "codepen.io",
  },
  {
    name: "Reddit",
    urlTemplate: "https://www.reddit.com/user/{username}/",
    notFoundMarkers: [
      "nobody on reddit goes by that name",
      "sorry, nobody on reddit goes by that name",
      "this account has been banned",
    ],
    existsMarkers: ["karma", "cake day", "post karma"],
    category: "social",
    domain: "reddit.com",
  },
  {
    name: "Hacker News",
    urlTemplate: "https://news.ycombinator.com/user?id={username}",
    notFoundMarkers: ["no such user."],
    existsMarkers: ["created:", "karma:"],
    category: "social",
    domain: "news.ycombinator.com",
  },
  {
    name: "Lobsters",
    urlTemplate: "https://lobste.rs/u/{username}",
    notFoundMarkers: ["page not found", "404 not found"],
    existsMarkers: ["karma:", "stories submitted"],
    category: "social",
    domain: "lobste.rs",
  },
  {
    name: "Behance",
    urlTemplate: "https://www.behance.net/{username}",
    notFoundMarkers: ["we couldn't find anything", "page not found"],
    existsMarkers: ["project views", "appreciations", "followers"],
    category: "creative",
    domain: "behance.net",
  },
  {
    name: "Dribbble",
    urlTemplate: "https://dribbble.com/{username}",
    notFoundMarkers: ["whoops, that page is gone", "page not found"],
    existsMarkers: ["shots", "followers", "likes"],
    category: "creative",
    domain: "dribbble.com",
  },
  {
    name: "ArtStation",
    urlTemplate: "https://www.artstation.com/{username}",
    notFoundMarkers: ["page not found", "we couldn't find the page"],
    existsMarkers: ["artwork", "followers", "following"],
    category: "creative",
    domain: "artstation.com",
  },
  {
    name: "DeviantArt",
    urlTemplate: "https://www.deviantart.com/{username}",
    notFoundMarkers: ["deviantart 404", "the page you were looking for doesn't exist"],
    existsMarkers: ["deviations", "watchers", "pageviews"],
    category: "creative",
    domain: "deviantart.com",
  },
  {
    name: "Medium",
    urlTemplate: "https://medium.com/@{username}",
    notFoundMarkers: ["page not found", "404: not found", "out of nothing, something"],
    existsMarkers: ["followers", "following", "stories"],
    category: "writing",
    domain: "medium.com",
  },
  {
    name: "Keybase",
    urlTemplate: "https://keybase.io/{username}",
    notFoundMarkers: ["page not found", "user not found", "404 - not found"],
    existsMarkers: ["public key", "identities", "proofs"],
    category: "identity",
    domain: "keybase.io",
  },
  {
    name: "About.me",
    urlTemplate: "https://about.me/{username}",
    notFoundMarkers: ["page not found", "we could not find"],
    existsMarkers: ["biography", "contact", "view profile"],
    category: "identity",
    domain: "about.me",
  },
  {
    name: "Linktree",
    urlTemplate: "https://linktr.ee/{username}",
    notFoundMarkers: ["this linktree is not available", "profile not found"],
    existsMarkers: ["linktree", "links"],
    category: "identity",
    domain: "linktr.ee",
  },
];

const USERNAME_RE = /^[A-Za-z0-9_.-]{2,30}$/;

export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

export function validateUsername(value: string): string {
  const trimmed = value.trim();
  if (!USERNAME_RE.test(trimmed)) {
    throw new Error("Use 2–30 letters, numbers, dots, underscores, or hyphens.");
  }
  return trimmed;
}

export function providerCount(): number {
  return PROVIDERS.length;
}

export async function checkProvider(
  provider: Provider,
  username: string
): Promise<CheckResult> {
  const targetUrl = provider.urlTemplate.replace("{username}", encodeURIComponent(username));
  const checkedAt = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6500);

    const response = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
      },
      redirect: "follow",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const status = response.status;
    const finalUrl = response.url || targetUrl;

    // Check if redirect ended up on generic login or home page
    const redirectedToAuthOrHome =
      finalUrl.includes("/login") ||
      finalUrl.includes("/sign_in") ||
      finalUrl.includes("/users/sign_in") ||
      (finalUrl.replace(/\/$/, "") === `https://${provider.domain}`);

    let state: "candidate" | "not_found" | "inconclusive" = "inconclusive";
    let confidence: "none" | "low" | "medium" | "high" = "none";
    let detail = "";

    if (redirectedToAuthOrHome && status === 200) {
      state = "not_found";
      confidence = "none";
      detail = "Redirected to login or homepage; profile does not exist.";
    } else if (status === 200) {
      const text = await response.text();
      const body = text.slice(0, 180000).toLowerCase();

      const matchedNotFound = provider.notFoundMarkers.some((m) =>
        body.includes(m.toLowerCase())
      );

      if (matchedNotFound) {
        state = "not_found";
        confidence = "none";
        detail = "Page returned 200 but contains provider not-found markers.";
      } else if (
        provider.existsMarkers.length > 0 &&
        provider.existsMarkers.some((m) => body.includes(m.toLowerCase()))
      ) {
        state = "candidate";
        confidence = "high";
        detail = "Verified public profile signals found on page.";
      } else {
        state = "candidate";
        confidence = "medium";
        detail = "Public profile page responded 200 OK. Manually verify identity ownership.";
      }
    } else if (status === 404) {
      state = "not_found";
      confidence = "none";
      detail = "Provider returned HTTP 404 Not Found.";
    } else if (status === 401 || status === 403 || status === 429) {
      state = "inconclusive";
      confidence = "none";
      detail = `Provider restricted access or rate-limited (HTTP ${status}).`;
    } else {
      state = "inconclusive";
      confidence = "none";
      detail = `Provider responded with HTTP ${status}.`;
    }

    return {
      provider: provider.name,
      category: provider.category,
      profile_url: targetUrl,
      domain: provider.domain,
      status: state,
      http_status: status,
      confidence,
      detail,
      checked_at: checkedAt,
    };
  } catch (err: any) {
    const isAbort = err?.name === "AbortError";
    return {
      provider: provider.name,
      category: provider.category,
      profile_url: targetUrl,
      domain: provider.domain,
      status: "inconclusive",
      http_status: null,
      confidence: "none",
      detail: isAbort ? "Request timed out" : `Network error: ${err?.message || "Connection failed"}`,
      checked_at: checkedAt,
    };
  }
}

export async function searchUsername(username: string): Promise<CheckResult[]> {
  const valid = validateUsername(username);
  const promises = PROVIDERS.map((p) => checkProvider(p, valid));
  return Promise.all(promises);
}
