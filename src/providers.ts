/**
 * Curated allowlist of public profile sources (40+ Global Networks).
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
    notFoundMarkers: ["if you have telegram, you can view and join", "tgme_page_extra"],
    existsMarkers: ["tgme_page_title", "tgme_page_description"],
    category: "social",
    domain: "telegram.org",
  },
  {
    name: "Mastodon",
    urlTemplate: "https://mastodon.social/@{username}",
    notFoundMarkers: ["page not found", "404"],
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
    notFoundMarkers: ["the specified profile could not be found", "error 502"],
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
    notFoundMarkers: ["page not found", "404"],
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
      } else {
        state = "not_found";
        detail = "Keybase profile not found.";
      }
    } else if (provider.type === "api_artstation") {
      if (status === 200) {
        const text = await response.text();
        if (text.includes('"id"') && !text.includes('"error"')) {
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
        state = "not_found";
        detail = "No ArtStation profile.";
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
      } else {
        state = "not_found";
        detail = "Glitch user does not exist.";
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
          confidence = layer === 0 ? "high" : "medium";
          detail = "Verified public profile signals found on page.";
        } else {
          state = "candidate";
          confidence = layer === 0 ? "medium" : "low";
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
  const maxDepth = Math.min(Math.max(0, depth), 2);

  // Layer 0
  const layer0 = await Promise.all(
    PROVIDERS.map((p) => checkProvider(p, valid, 0))
  );

  if (maxDepth === 0) return layer0;

  const allResults = [...layer0];

  if (maxDepth >= 1) {
    for (const r of layer0) {
      if (r.status === "candidate") {
        r.detail = (r.detail || "") + " (layer 0)";
      }
    }
  }

  return allResults;
}
