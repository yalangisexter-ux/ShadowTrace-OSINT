"""Fixed allowlist of public profile checks. Never accepts arbitrary URLs."""
from dataclasses import dataclass
import asyncio
import re
from datetime import datetime, timezone
import httpx

@dataclass(frozen=True)
class Provider:
    name: str
    url_template: str
    not_found_markers: tuple[str, ...] = ()
    exists_markers: tuple[str, ...] = ()
    category: str = "code"

# Curated high-signal public profile sources only.
PROVIDERS: tuple[Provider, ...] = (
    Provider("GitHub", "https://github.com/{username}",
             ("<title>page not found", "not found", "404"),
             ("followers", "repositories", "joined"), "code"),
    Provider("GitLab", "https://gitlab.com/{username}",
             ("<title>404", "page not found"), (), "code"),
    Provider("Codeberg", "https://codeberg.org/{username}",
             ("<title>page not found", "not found"), (), "code"),
    Provider("Bitbucket", "https://bitbucket.org/{username}/",
             ("page not found", "repository not found"), (), "code"),
    Provider("SourceHut", "https://sr.ht/~{username}",
             ("page not found", "not found"), (), "code"),
    Provider("DEV Community", "https://dev.to/{username}",
             ("<title>page not found", "not found"), (), "code"),
    Provider("Hashnode", "https://hashnode.com/@{username}",
             ("page not found", "user not found"), (), "code"),
    Provider("Replit", "https://replit.com/@{username}",
             ("page not found", "not found"), (), "code"),
    Provider("Glitch", "https://glitch.com/@{username}",
             ("page not found", "not found"), (), "code"),
    Provider("CodePen", "https://codepen.io/{username}",
             ("page not found", "404"), (), "code"),
    Provider("Reddit", "https://www.reddit.com/user/{username}/",
             ("page not found", "nobody on reddit goes by that name", "sorry, nobody on reddit"), (), "social"),
    Provider("Hacker News", "https://news.ycombinator.com/user?id={username}",
             ("no such user", "user not found"), (), "social"),
    Provider("Lobsters", "https://lobste.rs/u/{username}",
             ("page not found", "not found"), (), "social"),
    Provider("Behance", "https://www.behance.net/{username}",
             ("page not found", "not found"), (), "creative"),
    Provider("Dribbble", "https://dribbble.com/{username}",
             ("page not found", "not found"), (), "creative"),
    Provider("ArtStation", "https://www.artstation.com/{username}",
             ("page not found", "not found"), (), "creative"),
    Provider("DeviantArt", "https://www.deviantart.com/{username}",
             ("page not found", "deviantart 404"), (), "creative"),
    Provider("Medium", "https://medium.com/@{username}",
             ("page not found", "not found"), (), "writing"),
    Provider("Keybase", "https://keybase.io/{username}",
             ("page not found", "user not found"), (), "identity"),
    Provider("About.me", "https://about.me/{username}",
             ("page not found", "not found"), (), "identity"),
    Provider("Linktree", "https://linktr.ee/{username}",
             ("page not found", "this linktree is not available"), (), "identity"),
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,30}$")
USER_AGENT = "ShadowTraceOSINT/0.2 (+public-profile-research; respectful)"

def validate_username(value: str) -> str:
    value = value.strip()
    if not USERNAME_RE.fullmatch(value):
        raise ValueError("Use 2–30 letters, numbers, dots, underscores, or hyphens.")
    return value

async def _check(client: httpx.AsyncClient, provider: Provider, username: str) -> dict:
    url = provider.url_template.format(username=username)
    checked = datetime.now(timezone.utc).isoformat()
    try:
        response = await client.get(url, follow_redirects=False)
        status = response.status_code
        body = response.text[:180_000].lower()
        if status == 200:
            if any(m in body for m in provider.not_found_markers):
                state, confidence, detail = "not_found", "none", "Page returned 200 but contains not-found markers."
            elif provider.exists_markers and any(m in body for m in provider.exists_markers):
                state, confidence, detail = "candidate", "medium", "Public profile page responded with positive signals. Manually verify ownership."
            else:
                state, confidence, detail = "candidate", "low", "Public profile page responded. Manually verify it belongs to the intended subject."
        elif status == 404:
            state, confidence, detail = "not_found", "none", "Provider returned HTTP 404."
        elif status in (401, 403, 429):
            state, confidence, detail = "inconclusive", "none", f"Provider restricted or rate-limited the request (HTTP {status})."
        elif 300 <= status < 400:
            state, confidence, detail = "inconclusive", "none", f"Redirect received (HTTP {status}); not followed automatically."
        else:
            state, confidence, detail = "inconclusive", "none", f"Unexpected provider response (HTTP {status})."
        return {
            "provider": provider.name,
            "category": provider.category,
            "profile_url": url,
            "status": state,
            "http_status": status,
            "confidence": confidence,
            "detail": detail,
            "checked_at": checked,
        }
    except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
        return {
            "provider": provider.name,
            "category": provider.category,
            "profile_url": url,
            "status": "inconclusive",
            "http_status": None,
            "confidence": "none",
            "detail": f"Request failed: {type(exc).__name__}",
            "checked_at": checked,
        }
    except Exception as exc:
        return {
            "provider": provider.name,
            "category": provider.category,
            "profile_url": url,
            "status": "inconclusive",
            "http_status": None,
            "confidence": "none",
            "detail": f"Unexpected error: {type(exc).__name__}",
            "checked_at": checked,
        }

async def search_username(username: str, max_concurrent: int = 8) -> list[dict]:
    username = validate_username(username)
    limits = httpx.Limits(max_connections=max_concurrent, max_keepalive_connections=max_concurrent)
    timeout = httpx.Timeout(7.0, connect=3.5)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, headers={"User-Agent": USER_AGENT}) as client:
        tasks = [_check(client, p, username) for p in PROVIDERS]
        return await asyncio.gather(*tasks)

def provider_count() -> int:
    return len(PROVIDERS)
