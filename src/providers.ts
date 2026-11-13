/**
 * Curated allowlist of public profile sources.
 * Never accepts arbitrary URLs.
 */

export interface Provider {
  name: string;
  urlTemplate: string;
  notFoundMarkers: string[];
  existsMarkers: string[];
  category: string;
}

export interface CheckResult {
  provider: string;
  category: string;
  profile_url: string;
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
    notFoundMarkers: ["<title>page not found", "not found", "404"],
    existsMarkers: ["followers", "repositories", "joined"],
    category: "code",
  },
  {
    name: "GitLab",
    urlTemplate: "https://gitlab.com/{username}",
    notFoundMarkers: ["<title>404", "page not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Codeberg",
    urlTemplate: "https://codeberg.org/{username}",
    notFoundMarkers: ["<title>page not found", "not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Bitbucket",
    urlTemplate: "https://bitbucket.org/{username}/",
    notFoundMarkers: ["page not found", "repository not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "SourceHut",
    urlTemplate: "https://sr.ht/~{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "DEV Community",
    urlTemplate: "https://dev.to/{username}",
    notFoundMarkers: ["<title>page not found", "not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Hashnode",
    urlTemplate: "https://hashnode.com/@{username}",
    notFoundMarkers: ["page not found", "user not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Replit",
    urlTemplate: "https://replit.com/@{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Glitch",
    urlTemplate: "https://glitch.com/@{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "CodePen",
    urlTemplate: "https://codepen.io/{username}",
    notFoundMarkers: ["page not found", "404"],
    existsMarkers: [],
    category: "code",
  },
  {
    name: "Reddit",
    urlTemplate: "https://www.reddit.com/user/{username}/",
    notFoundMarkers: [
      "page not found",
      "nobody on reddit goes by that name",
      "sorry, nobody on reddit",
    ],
    existsMarkers: [],
    category: "social",
  },
  {
    name: "Hacker News",
    urlTemplate: "https://news.ycombinator.com/user?id={username}",
    notFoundMarkers: ["no such user", "user not found"],
    existsMarkers: [],
    category: "social",
  },
  {
    name: "Lobsters",
    urlTemplate: "https://lobste.rs/u/{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "social",
  },
  {
    name: "Behance",
    urlTemplate: "https://www.behance.net/{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "creative",
  },
  {
    name: "Dribbble",
    urlTemplate: "https://dribbble.com/{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "creative",
  },
  {
    name: "ArtStation",
    urlTemplate: "https://www.artstation.com/{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "creative",
  },
  {
    name: "DeviantArt",
    urlTemplate: "https://www.deviantart.com/{username}",
    notFoundMarkers: ["page not found", "deviantart 404"],
    existsMarkers: [],
    category: "creative",
  },
  {
    name: "Medium",
    urlTemplate: "https://medium.com/@{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "writing",
  },
  {
    name: "Keybase",
    urlTemplate: "https://keybase.io/{username}",
    notFoundMarkers: ["page not found", "user not found"],
    existsMarkers: [],
    category: "identity",
  },
  {
    name: "About.me",
    urlTemplate: "https://about.me/{username}",
    notFoundMarkers: ["page not found", "not found"],
    existsMarkers: [],
    category: "identity",
  },
  {
    name: "Linktree",
    urlTemplate: "https://linktr.ee/{username}",
    notFoundMarkers: ["page not found", "this linktree is not available"],
    existsMarkers: [],
    category: "identity",
  },
];

const USERNAME_RE = /^[A-Za-z0-9_.-]{2,30}$/;
export const USER_AGENT =
  "ShadowTraceOSINT/0.2 (+public-profile-research; respectful)";

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
  const url = provider.urlTemplate.replace("{username}", encodeURIComponent(username));
  const checkedAt = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 7000);

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "manual",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const status = response.status;
    let state: "candidate" | "not_found" | "inconclusive" = "inconclusive";
    let confidence: "none" | "low" | "medium" | "high" = "none";
    let detail = "";

    if (status === 200) {
      const text = await response.text();
      const body = text.slice(0, 180000).toLowerCase();

      if (provider.notFoundMarkers.some((m) => body.includes(m.toLowerCase()))) {
        state = "not_found";
        confidence = "none";
        detail = "Page returned 200 but contains not-found markers.";
      } else if (
        provider.existsMarkers.length > 0 &&
        provider.existsMarkers.some((m) => body.includes(m.toLowerCase()))
      ) {
        state = "candidate";
        confidence = "medium";
        detail = "Public profile page responded with positive signals. Manually verify ownership.";
      } else {
        state = "candidate";
        confidence = "low";
        detail = "Public profile page responded. Manually verify it belongs to the intended subject.";
      }
    } else if (status === 404) {
      state = "not_found";
      confidence = "none";
      detail = "Provider returned HTTP 404.";
    } else if (status === 401 || status === 403 || status === 429) {
      state = "inconclusive";
      confidence = "none";
      detail = `Provider restricted or rate-limited the request (HTTP ${status}).`;
    } else if (status >= 300 && status < 400) {
      state = "inconclusive";
      confidence = "none";
      detail = `Redirect received (HTTP ${status}); not followed automatically.`;
    } else {
      state = "inconclusive";
      confidence = "none";
      detail = `Unexpected provider response (HTTP ${status}).`;
    }

    return {
      provider: provider.name,
      category: provider.category,
      profile_url: url,
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
      profile_url: url,
      status: "inconclusive",
      http_status: null,
      confidence: "none",
      detail: isAbort ? "Request timed out" : `Request failed: ${err?.message || "Network error"}`,
      checked_at: checkedAt,
    };
  }
}

export async function searchUsername(username: string): Promise<CheckResult[]> {
  const valid = validateUsername(username);
  // Execute checks concurrently across Cloudflare's edge network
  const promises = PROVIDERS.map((p) => checkProvider(p, valid));
  return Promise.all(promises);
}
