/**
 * Curated allowlist of 34 public profile sources.
 * Features specialized API and pattern probes to eliminate SPA false positives.
 * Includes bounded Deep Search (recursive username pivoting).
 */

export interface Provider {
  name: string;
  urlTemplate: string;
  checkUrl?: string; // Optional dedicated API endpoint
  type?: "api_github" | "api_gitlab" | "api_reddit" | "api_hn" | "api_keybase" | "api_artstation" | "api_glitch" | "api_chess" | "api_lichess" | "api_docker" | "html";
  notFoundMarkers: string[];
  existsMarkers: string[];
  category: "code" | "social" | "creative" | "writing" | "identity" | "gaming";
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
  layer?: number;
  seed?: string;
  identity_name?: string;
  identifier_display?: string;
  fields_count?: number;
  extra_fields?: Record<string, string>;
  verified?: boolean;
}

export const PROVIDERS: Provider[] = [
  // --- 1. Code & Developer Platforms ---
  {
    name: "GitHub",
    urlTemplate: "https://github.com/{username}",
    checkUrl: "https://api.github.com/users/{username}",
    type: "api_github",
    notFoundMarkers: ["not found"],
    existsMarkers: [],
    category: "code",
    domain: "github.com",
  },
  {
    name: "GitLab",
    urlTemplate: "https://gitlab.com/{username}",
    checkUrl: "https://gitlab.com/api/v4/users?username={username}",
    type: "api_gitlab",
    notFoundMarkers: [],
    existsMarkers: [],
    category: "code",
    domain: "gitlab.com",
  },
  {
    name: "Codeberg",
    urlTemplate: "https://codeberg.org/{username}",
    notFoundMarkers: ["<title>page not found", "404 - page not found"],
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
    notFoundMarkers: ["<title>page not found", "this page does not exist", "404 - page not found"],
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
    checkUrl: "https://api.glitch.com/v1/users/by/login?login={username}",
    type: "api_glitch",
    notFoundMarkers: ["not found", "could not find user"],
    existsMarkers: [],
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
    name: "Docker Hub",
    urlTemplate: "https://hub.docker.com/u/{username}",
    checkUrl: "https://hub.docker.com/v2/users/{username}/",
    type: "api_docker",
    notFoundMarkers: [],
    existsMarkers: [],
    category: "code",
    domain: "docker.com",
  },
  {
    name: "npm",
    urlTemplate: "https://www.npmjs.com/~{username}",
    notFoundMarkers: ["packages not found", "user not found", "404 not found"],
    existsMarkers: ["packages", "collaborator"],
    category: "code",
    domain: "npmjs.com",
  },
  {
    name: "PyPI",
    urlTemplate: "https://pypi.org/user/{username}/",
    notFoundMarkers: ["404 not found", "we looked everywhere"],
    existsMarkers: ["projects"],
    category: "code",
    domain: "pypi.org",
  },

  // --- 2. Social & Discussion Communities ---
  {
    name: "Reddit",
    urlTemplate: "https://www.reddit.com/user/{username}/",
    checkUrl: "https://www.reddit.com/user/{username}/about.json",
    type: "api_reddit",
    notFoundMarkers: ["nobody on reddit goes by that name"],
    existsMarkers: [],
    category: "social",
    domain: "reddit.com",
  },
  {
    name: "Hacker News",
    urlTemplate: "https://news.ycombinator.com/user?id={username}",
    checkUrl: "https://hacker-news.firebaseio.com/v0/user/{username}.json",
    type: "api_hn",
    notFoundMarkers: [],
    existsMarkers: [],
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
    name: "Telegram",
    urlTemplate: "https://t.me/{username}",
    notFoundMarkers: [],
    existsMarkers: ["tgme_page_title", "tgme_page_description"],
    category: "social",
    domain: "telegram.org",
  },
  {
    name: "Mastodon",
    urlTemplate: "https://mastodon.social/@{username}",
    notFoundMarkers: ["page not found", "account not found"],
    existsMarkers: ["account__header", "toots"],
    category: "social",
    domain: "mastodon.social",
  },

  // --- 3. Gaming & Esports Platforms ---
  {
    name: "Chess.com",
    urlTemplate: "https://www.chess.com/member/{username}",
    checkUrl: "https://api.chess.com/pub/player/{username}",
    type: "api_chess",
    notFoundMarkers: [],
    existsMarkers: [],
    category: "gaming",
    domain: "chess.com",
  },
  {
    name: "Lichess",
    urlTemplate: "https://lichess.org/@/{username}",
    checkUrl: "https://lichess.org/api/user/{username}",
    type: "api_lichess",
    notFoundMarkers: [],
    existsMarkers: [],
    category: "gaming",
    domain: "lichess.org",
  },
  {
    name: "Steam Community",
    urlTemplate: "https://steamcommunity.com/id/{username}",
    notFoundMarkers: ["the specified profile could not be found"],
    existsMarkers: ["profile_header", "actual_persona_name"],
    category: "gaming",
    domain: "steampowered.com",
  },

  // --- 4. Creative & Media Portfolios ---
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
    checkUrl: "https://www.artstation.com/users/{username}/quick.json",
    type: "api_artstation",
    notFoundMarkers: [],
    existsMarkers: [],
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
    name: "SoundCloud",
    urlTemplate: "https://soundcloud.com/{username}",
    notFoundMarkers: ["we can't find that user", "404 not found"],
    existsMarkers: ["tracks", "followers"],
    category: "creative",
    domain: "soundcloud.com",
  },

  // --- 5. Publishing & Writing ---
  {
    name: "Medium",
    urlTemplate: "https://medium.com/@{username}",
    notFoundMarkers: ["page not found", "404: not found", "out of nothing, something"],
    existsMarkers: ["followers", "following", "stories"],
    category: "writing",
    domain: "medium.com",
  },
  {
    name: "Substack",
    urlTemplate: "https://{username}.substack.com",
    notFoundMarkers: ["page not found", "doesn't exist"],
    existsMarkers: ["subscribe", "posts"],
    category: "writing",
    domain: "substack.com",
  },

  // --- 6. Identity, Bio & Funding ---
  {
    name: "Keybase",
    urlTemplate: "https://keybase.io/{username}",
    checkUrl: "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
    type: "api_keybase",
    notFoundMarkers: [],
    existsMarkers: [],
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
    notFoundMarkers: ["this linktree is not available", "profile not found", "page not found"],
    existsMarkers: ["linktree", "links"],
    category: "identity",
    domain: "linktr.ee",
  },
  {
    name: "Patreon",
    urlTemplate: "https://www.patreon.com/{username}",
    notFoundMarkers: ["page not found", "creator not found"],
    existsMarkers: ["patrons", "membership"],
    category: "identity",
    domain: "patreon.com",
  },
  {
    name: "Buy Me a Coffee",
    urlTemplate: "https://www.buymeacoffee.com/{username}",
    notFoundMarkers: ["page not found", "creator not found"],
    existsMarkers: ["supporter", "coffee"],
    category: "identity",
    domain: "buymeacoffee.com",
  },
  {
    name: "Product Hunt",
    urlTemplate: "https://www.producthunt.com/@{username}",
    notFoundMarkers: ["page not found"],
    existsMarkers: ["upvotes", "products"],
    category: "identity",
    domain: "producthunt.com",
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


export interface ProfileSignals {
  title: string;
  description: string;
  displayName: string;
  links: string[];
  titleMentionsUsername: boolean;
}

function decodeHtml(value: string): string {
  return value.replace(/&amp;/gi, "&").replace(/&#39;|&apos;/gi, "'").replace(/&quot;/gi, '"').replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").trim();
}

export function extractProfileSignals(html: string, username: string, baseUrl: string): ProfileSignals {
  const metaTags = html.match(/<meta\b[^>]*>/gi) || [];
  const meta = (property: string) => {
    for (const tag of metaTags) {
      const key = tag.match(/\b(?:property|name)\s*=\s*["']([^"']+)["']/i)?.[1];
      const value = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1];
      if (key === property && value) return decodeHtml(value);
    }
    return "";
  };
  const title = decodeHtml(meta("og:title") || html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "");
  const description = decodeHtml(meta("og:description") || meta("description") || "");
  const displayName = title.replace(/\s*[|·—-]\s*[^|·—-]+$/, "").trim();
  const links = new Set<string>();
  const anchorPattern = /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = anchorPattern.exec(html)) && links.size < 40) {
    try {
      const url = new URL(decodeHtml(match[1]), baseUrl);
      if (url.protocol === "https:" && !url.username && !url.password) {
        url.search = "";
        url.hash = "";
        links.add(url.toString());
      }
    } catch {}
  }
  return { title, description, displayName, links: Array.from(links), titleMentionsUsername: Boolean(title && title.toLowerCase().includes(username.toLowerCase())) };
}

interface PageFingerprint { title: string; words: Set<string>; }

function fingerprintHtml(html: string): PageFingerprint {
  const title = decodeHtml(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "").toLowerCase();
  const text = html.replace(/<script\b[\s\S]*?<\/script>/gi, " ").replace(/<style\b[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/gi, " ").toLowerCase();
  const words = new Set((text.match(/[a-z0-9]{3,}/g) || []).filter(word => !["the", "and", "for", "with", "this", "that", "your", "from", "have", "page"].includes(word)));
  return { title, words };
}

export function isSoft404Page(candidateHtml: string, baselineHtml: string): boolean {
  const candidate = fingerprintHtml(candidateHtml);
  const baseline = fingerprintHtml(baselineHtml);
  if (!baseline.title && baseline.words.size === 0) return false;
  if (candidate.words.size < 8 || baseline.words.size < 8) return false;
  let overlap = 0;
  for (const word of candidate.words) if (baseline.words.has(word)) overlap++;
  const similarity = overlap / Math.max(candidate.words.size, baseline.words.size);
  if (candidate.title && baseline.title && candidate.title === baseline.title) return similarity >= 0.72;
  return similarity >= 0.88;
}

const soft404Baselines = new Map<string, Promise<string | null>>();
const SOFT404_CACHE_LIMIT = 256;
const BASELINE_PROBE_HOSTS = new Set(["codeberg.org", "dev.to", "hashnode.com", "replit.com", "codepen.io", "behance.net"]);

async function getSoft404Baseline(probeUrl: string, targetUrl: string, username: string): Promise<string | null> {
  const host = new URL(probeUrl).hostname.toLowerCase().replace(/^www\./, "");
  const cacheKey = host.endsWith(".substack.com") ? "substack.com" : host;
  let pending = soft404Baselines.get(cacheKey);
  if (!pending) {
    pending = (async () => {
      try {
        const sentinel = "shadowtrace-missing-" + crypto.randomUUID().replace(/-/g, "");
        const baselineUrl = host.endsWith(".substack.com")
          ? "https://substack.com/@" + sentinel
          : targetUrl.replace(encodeURIComponent(username), encodeURIComponent(sentinel));
        if (baselineUrl === targetUrl) return null;
        const response = await fetch(baselineUrl, {
          headers: { "User-Agent": USER_AGENT, "Accept": "text/html,*/*" },
          redirect: "follow",
          signal: AbortSignal.timeout(4500)
        });
        if (![200, 404].includes(response.status) || !response.url || !isAllowedFinalUrl(baselineUrl, response.url)) return null;
        const type = response.headers.get("content-type") || "";
        if (type && !type.includes("text/html")) return null;
        return (await response.text()).slice(0, 120000);
      } catch { return null; }
    })();
    soft404Baselines.set(cacheKey, pending);
    if (soft404Baselines.size > SOFT404_CACHE_LIMIT) {
      const oldest = soft404Baselines.keys().next().value;
      if (oldest) soft404Baselines.delete(oldest);
    }
  } else {
    soft404Baselines.delete(cacheKey);
    soft404Baselines.set(cacheKey, pending);
  }
  return pending;
}

export function isAllowedFinalUrl(probeUrl: string, finalUrl: string): boolean {
  try {
    const expected = new URL(probeUrl).hostname.toLowerCase().replace(/^www\./, "");
    const actual = new URL(finalUrl).hostname.toLowerCase().replace(/^www\./, "");
    return actual === expected || actual.endsWith("." + expected);
  } catch { return false; }
}

function extractPivotUsernames(links: string[], displayName: string, rootUsername: string): string[] {
  const knownHosts = new Set(PROVIDERS.map(provider => {
    try { return new URL(provider.urlTemplate.replace("{username}", "shadowtrace")).hostname.toLowerCase().replace(/^www\./, ""); }
    catch { return ""; }
  }));
  const found = new Set<string>();
  for (const link of links) {
    try {
      const url = new URL(link);
      if (!knownHosts.has(url.hostname.toLowerCase().replace(/^www\./, ""))) continue;
      const segments = url.pathname.split("/").filter(Boolean);
      const raw = segments[segments.length - 1]?.replace(/^@/, "").replace(/^~/, "");
      if (raw && USERNAME_RE.test(raw) && raw.toLowerCase() !== rootUsername.toLowerCase()) found.add(raw);
    } catch {}
  }
  for (const match of displayName.matchAll(/@([A-Za-z0-9_.-]{2,30})/g)) {
    if (match[1].toLowerCase() !== rootUsername.toLowerCase()) found.add(match[1]);
  }
  return Array.from(found).slice(0, 3);
}

async function mapWithConcurrency<T, R>(items: T[], concurrency: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const output = new Array<R>(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      output[index] = await mapper(items[index]);
    }
  }));
  return output;
}

export async function checkProvider(
  provider: Provider,
  username: string,
  layer = 0,
  seed?: string
): Promise<CheckResult> {
  const targetUrl = provider.urlTemplate.replace("{username}", encodeURIComponent(username));
  const probeUrl = (provider.checkUrl || provider.urlTemplate).replace("{username}", encodeURIComponent(username));
  const checkedAt = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6500);

    const response = await fetch(probeUrl, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": provider.type?.startsWith("api_") 
          ? "application/json,text/plain,*/*" 
          : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
      },
      redirect: "follow",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const status = response.status;
    const finalUrl = response.url || probeUrl;
    if (!isAllowedFinalUrl(probeUrl, finalUrl)) {
      return { provider: provider.name, category: provider.category, profile_url: targetUrl, domain: provider.domain, status: "inconclusive", http_status: status, confidence: "none", detail: "Provider redirected outside its own host; response rejected.", checked_at: checkedAt, layer, seed };
    }

    let state: "candidate" | "not_found" | "inconclusive" = "inconclusive";
    let confidence: "none" | "low" | "medium" | "high" = "none";
    let detail = "";
    let identityName: string | undefined;
    let identifierDisplay: string | undefined;
    let fieldsCount = 1;
    let extraFields: Record<string, string> = {};

    // 1. Specialized API probes
    if (provider.type === "api_github") {
      let isGithubCandidate = false;
      let ghBio = "";
      let ghName = "";
      let ghAvatar = `https://github.com/${username}.png`;
      let ghRepos = 0;
      let ghFollowers = 0;

      if (status === 200) {
        try {
          const d: any = await response.json();
          isGithubCandidate = true;
          ghRepos = d.public_repos ?? 0;
          ghFollowers = d.followers ?? 0;
          ghBio = d.bio || "";
          ghName = d.name || "";
          ghAvatar = d.avatar_url || ghAvatar;
        } catch {}
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "GitHub user does not exist.";
      } else {
        // Fallback: Check GitHub direct endpoint & HTML
        try {
          const imgRes = await fetch(`https://github.com/${encodeURIComponent(username)}.png`, {
            method: "GET",
            headers: { "User-Agent": USER_AGENT },
            redirect: "manual",
          });
          if (imgRes.status === 302 || imgRes.status === 200) {
            isGithubCandidate = true;
            const htmlRes = await fetch(`https://github.com/${encodeURIComponent(username)}`, {
              method: "GET",
              headers: { "User-Agent": USER_AGENT },
            });
            if (htmlRes.ok) {
              const html = await htmlRes.text();
              const titleMatch = html.match(/<title>(.*?)\((.*?)\) · GitHub<\/title>/i);
              if (titleMatch && titleMatch[2]) {
                ghName = titleMatch[2].trim();
              }
            }
          } else if (imgRes.status === 404) {
            state = "not_found";
            confidence = "none";
            detail = "GitHub user does not exist.";
          }
        } catch {}
      }

      if (isGithubCandidate) {
        state = "candidate";
        confidence = "high";
        identityName = ghName || username;
        identifierDisplay = `@${username}`;
        fieldsCount = 3;
        extraFields = {
          "Full Name": ghName || username,
          "Profile": targetUrl,
          "Avatar": ghAvatar,
          ...(ghRepos ? { "Public Repositories": String(ghRepos) } : {}),
          ...(ghFollowers ? { "Followers": String(ghFollowers) } : {}),
          ...(ghBio ? { "Bio": ghBio } : {})
        };
        detail = `Active GitHub profile (${ghName ? ghName + ' · ' : ''}@${username}).`;
      }
    } else if (provider.type === "api_gitlab") {
      let isGitlabCandidate = false;
      let glName = "";
      let glId = "";

      if (status === 200) {
        try {
          const arr: any = await response.json();
          if (Array.isArray(arr) && arr.length > 0) {
            isGitlabCandidate = true;
            glId = String(arr[0].id);
            glName = arr[0].name || username;
          } else {
            state = "not_found";
            confidence = "none";
            detail = "GitLab user does not exist.";
          }
        } catch {}
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "GitLab user does not exist.";
      } else {
        // Fallback: Check GitLab HTML page
        try {
          const glRes = await fetch(`https://gitlab.com/${encodeURIComponent(username)}`, {
            method: "GET",
            headers: { "User-Agent": USER_AGENT },
          });
          if (glRes.status === 200) {
            isGitlabCandidate = true;
            const html = await glRes.text();
            const titleMatch = html.match(/<title>(.*?) · GitLab<\/title>/i);
            if (titleMatch && titleMatch[1]) {
              glName = titleMatch[1].trim();
            }
          }
        } catch {}
      }

      if (isGitlabCandidate) {
        state = "candidate";
        confidence = "high";
        identityName = glName || username;
        identifierDisplay = `GitLab: @${username}`;
        fieldsCount = 2;
        extraFields = {
          "Name": glName || username,
          "Profile": targetUrl,
          ...(glId ? { "User ID": glId } : {})
        };
        detail = `Active GitLab account (${glName || username}).`;
      }
    } else if (provider.type === "api_chess") {
      if (status === 200) {
        const d: any = await response.json();
        state = "candidate";
        confidence = "high";
        identityName = d.name || username;
        identifierDisplay = `Chess.com: @${d.username || username}`;
        fieldsCount = 3;
        extraFields = {
          "Player": d.name || username,
          "Player ID": String(d.player_id || ""),
          "Status": d.status || "active"
        };
        detail = `Active Chess.com player (ID: ${d.player_id ?? d.username}, Status: ${d.status || "active"}).`;
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "No Chess.com account exists with this username.";
      } else {
        state = "inconclusive";
        detail = `Chess.com API responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_lichess") {
      if (status === 200) {
        const d: any = await response.json();
        state = "candidate";
        confidence = "high";
        identityName = d.username || username;
        identifierDisplay = `Lichess: @${d.username || username}`;
        fieldsCount = 2;
        extraFields = {
          "Player": d.username || username,
          "Total Games": String(d.count?.all || 0)
        };
        detail = `Active Lichess player (Play count: ${d.count?.all ?? 0}, Seen: ${d.seenAt ? new Date(d.seenAt).toISOString().slice(0,10) : "recently"}).`;
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "No Lichess player exists with this handle.";
      } else {
        state = "inconclusive";
        detail = `Lichess responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_docker") {
      if (status === 200) {
        const d: any = await response.json();
        state = "candidate";
        confidence = "high";
        identityName = d.username || username;
        identifierDisplay = `Docker Hub: @${d.username || username}`;
        fieldsCount = 3;
        extraFields = {
          "Username": d.username || username,
          "Account Type": d.type || "Developer",
          "Registry": "Docker Hub"
        };
        detail = `Active Docker Hub publisher account (@${d.username || username}).`;
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "Docker Hub account does not exist.";
      } else {
        state = "inconclusive";
        detail = `Docker Hub API responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_hn") {
      if (status === 200) {
        const text = await response.text();
        if (!text || text.trim() === "null") {
          state = "not_found";
          confidence = "none";
          detail = "No Hacker News account exists with this username.";
        } else {
          const d: any = JSON.parse(text);
          state = "candidate";
          confidence = "high";
          identityName = username;
          identifierDisplay = `Hacker News: @${username}`;
          fieldsCount = 2;
          extraFields = {
            "Karma": String(d.karma ?? 0),
            "Registered": d.created ? new Date(d.created * 1000).toISOString().slice(0, 10) : "Active"
          };
          detail = `Verified Hacker News user (Karma: ${d.karma ?? 0}).`;
        }
      } else if (status === 404) {
        state = "not_found";
        detail = "Hacker News user not found.";
      } else {
        state = "inconclusive";
        detail = `Hacker News responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_keybase") {
      if (status === 200) {
        const d: any = await response.json();
        if (d.them && d.them[0] && d.them[0].id) {
          state = "candidate";
          confidence = "high";
          identityName = username;
          identifierDisplay = `Keybase: ${username}`;
          fieldsCount = 2;
          extraFields = {
            "Keybase UID": d.them[0].id,
            "Verification": "Cryptographically Verified PGP"
          };
          detail = `Verified Keybase cryptographic identity.`;
        } else {
          state = "not_found";
          confidence = "none";
          detail = "Keybase user does not exist.";
        }
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "Keybase profile not found.";
      } else {
        state = "inconclusive";
        detail = `Keybase API responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_artstation") {
      if (status === 200) {
        const text = await response.text();
        let payload: any = null;
        try { payload = JSON.parse(text); } catch {}
        if (payload && typeof payload === "object" && !Array.isArray(payload) && (typeof payload.id === "number" || (typeof payload.id === "string" && payload.id.length > 0)) && !payload.error) {
          state = "candidate";
          confidence = "high";
          identityName = username;
          identifierDisplay = `ArtStation: @${username}`;
          fieldsCount = 2;
          extraFields = {
            "Platform": "ArtStation",
            "Profile": targetUrl
          };
          detail = "Verified ArtStation creator profile.";
        } else {
          state = "not_found";
          confidence = "none";
          detail = "ArtStation artist profile does not exist.";
        }
      } else if (status === 404) {
        state = "not_found";
        detail = "ArtStation artist profile does not exist.";
      } else {
        state = "inconclusive";
        detail = `ArtStation API responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_glitch") {
      if (status === 200) {
        const d: any = await response.json();
        if (d && d.id) {
          state = "candidate";
          confidence = "high";
          identityName = username;
          identifierDisplay = `Glitch: @${username}`;
          fieldsCount = 2;
          extraFields = {
            "Glitch ID": String(d.id),
            "Platform": "Glitch Web Development"
          };
          detail = `Active Glitch developer account (ID: ${d.id}).`;
        } else {
          state = "not_found";
          detail = "Glitch user does not exist.";
        }
      } else if (status === 404) {
        state = "not_found";
        confidence = "none";
        detail = "Glitch user does not exist.";
      } else {
        state = "inconclusive";
        detail = `Glitch API responded HTTP ${status}.`;
      }
    } else if (provider.type === "api_reddit") {
      if (status === 200) {
        const d: any = await response.json();
        if (d.data && d.data.name) {
          state = "candidate";
          confidence = "high";
          identityName = d.data.name;
          identifierDisplay = `u/${d.data.name}`;
          fieldsCount = 2;
          extraFields = {
            "Total Karma": String(d.data.total_karma ?? 0),
            "Account": "Verified Reddit User"
          };
          detail = `Active Reddit account (Karma: ${d.data.total_karma ?? 0}).`;
        } else {
          state = "not_found";
          detail = "Nobody on Reddit goes by that name.";
        }
      } else if (status === 404) {
        state = "not_found";
        detail = "Nobody on Reddit goes by that name.";
      } else {
        state = "inconclusive";
        detail = "Reddit restricted external lookup (HTTP 403 / anti-bot).";
      }
    }
    // 2. Standard HTML inspection with redirect awareness
    else {
      const redirectedToAuthOrHome =
        finalUrl.includes("/login") ||
        finalUrl.includes("/sign_in") ||
        finalUrl.includes("/users/sign_in") ||
        (finalUrl.replace(/\/$/, "") === `https://${provider.domain}`);

      if (status && status >= 300 && status < 400) {
        const loc = (response.headers.get("location") || "").toLowerCase();
        if (
          loc.includes("/login") ||
          loc.includes("/sign_in") ||
          loc.includes("/users/sign_in") ||
          loc === "/" ||
          loc === `https://${provider.domain}` ||
          loc === `https://${provider.domain}/` ||
          loc === `http://${provider.domain}` ||
          loc === `http://${provider.domain}/`
        ) {
          state = "not_found";
          confidence = "none";
          detail = "Provider redirected to login or homepage; profile does not exist.";
        } else {
          state = "candidate";
          confidence = layer === 0 ? "high" : "medium";
          detail = `Provider profile active with canonical redirect.`;
        }
      } else if (redirectedToAuthOrHome && status === 200) {
        state = "not_found";
        confidence = "none";
        detail = "Redirected to login or homepage; profile does not exist.";
      } else if (status === 200) {
        const html = (await response.text()).slice(0, 180000);
        const body = html.toLowerCase();
        const matchedNotFound = provider.notFoundMarkers.some(marker => body.includes(marker.toLowerCase()));
        if (matchedNotFound) {
          state = "not_found";
          confidence = "none";
          detail = "Page contains a provider-specific not-found signal.";
        } else {
          const probeHost = new URL(probeUrl).hostname.toLowerCase().replace(/^www\./, "");
          const baseline = layer === 0 && BASELINE_PROBE_HOSTS.has(probeHost) ? await getSoft404Baseline(probeUrl, targetUrl, username) : null;
          if (baseline && isSoft404Page(html, baseline)) {
            state = "not_found";
            confidence = "none";
            detail = "Page matches this provider's missing-profile baseline (soft 404).";
          } else {
            const signals = extractProfileSignals(html, username, finalUrl);
            const markerMatch = provider.existsMarkers.some(marker => body.includes(marker.toLowerCase()));
            if (signals.titleMentionsUsername || markerMatch) {
              state = "candidate";
              confidence = signals.titleMentionsUsername && markerMatch ? "high" : "medium";
              identityName = signals.displayName || username;
              extraFields = {
                ...(signals.displayName ? { "Display name": signals.displayName } : {}),
                ...(signals.description ? { "Description": signals.description.slice(0, 300) } : {}),
                ...(signals.links.length ? { "Links": signals.links.join("\n") } : {})
              };
              detail = signals.titleMentionsUsername
                ? "Profile-specific page metadata matches the requested username."
                : "Provider profile markers found; identity ownership still requires manual review.";
            } else {
              state = "inconclusive";
              confidence = "none";
              detail = "HTTP 200 response lacked profile-specific evidence; not counted as a match.";
            }
          }
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
    }

    if (state === "candidate") {
      identityName = identityName || username;
      identifierDisplay = identifierDisplay || `@${username} on ${provider.name}`;
      fieldsCount = Math.max(fieldsCount, 1);
      extraFields = {
        "Platform": provider.name,
        "Profile URL": targetUrl,
        ...extraFields
      };
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
      layer,
      seed,
      identity_name: identityName,
      identifier_display: identifierDisplay,
      fields_count: fieldsCount,
      extra_fields: Object.keys(extraFields).length > 0 ? extraFields : undefined,
      verified: Boolean(provider.type?.startsWith("api_") && state === "candidate"),
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
      layer,
      seed,
    };
  }
}

export async function searchUsername(
  username: string,
  depth: number = 0
): Promise<CheckResult[]> {
  const valid = validateUsername(username);
  const maxDepth = Math.min(Math.max(0, Number.isFinite(depth) ? Math.floor(depth) : 0), 1);
  const seen = new Set<string>([valid.toLowerCase()]);
  const allResults: CheckResult[] = [];
  let current = [{ username: valid, seed: undefined as string | undefined }];

  for (let layer = 0; layer <= maxDepth && current.length > 0; layer++) {
    const deepSearchProviders = ["GitHub", "GitLab", "Reddit", "Keybase"];
    const providersForLayer = layer === 0 ? PROVIDERS : PROVIDERS.filter(provider => deepSearchProviders.includes(provider.name));
    const layerResults = await mapWithConcurrency(current.slice(0, 1), 1, async pivot =>
      mapWithConcurrency(providersForLayer, 4, provider => checkProvider(provider, pivot.username, layer, pivot.seed))
    );
    const flattened = layerResults.flat();
    allResults.push(...flattened);
    if (layer === maxDepth) break;

    const next: Array<{ username: string; seed: string }> = [];
    for (const result of flattened) {
      if (result.status !== "candidate" || result.confidence !== "high") continue;
      const links = (result.extra_fields?.Links || "").split("\n").filter(Boolean);
      const displayName = result.extra_fields?.["Display name"] || result.identity_name || "";
      for (const pivot of extractPivotUsernames(links, displayName, valid)) {
        const key = pivot.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        next.push({ username: pivot, seed: result.provider });
        if (next.length >= 1) break;
      }
      if (next.length >= 1) break;
    }
    current = next;
  }
  return allResults;
}
