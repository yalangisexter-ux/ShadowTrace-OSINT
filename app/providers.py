"""Fixed allowlist of public profile checks; never accepts arbitrary URLs."""
from dataclasses import dataclass
import asyncio, re
from datetime import datetime, timezone
import httpx

@dataclass(frozen=True)
class Provider:
    name: str
    url_template: str
    not_found_markers: tuple[str, ...] = ()

PROVIDERS = (
    Provider("GitHub", "https://github.com/{username}", ("<title>page not found",)),
    Provider("GitLab", "https://gitlab.com/{username}", ("<title>404",)),
    Provider("Reddit", "https://www.reddit.com/user/{username}/", ("page not found", "nobody on reddit goes by that name")),
    Provider("Codeberg", "https://codeberg.org/{username}", ("<title>page not found",)),
    Provider("DEV Community", "https://dev.to/{username}", ("<title>page not found",)),
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,30}$")
USER_AGENT = "ShadowTraceOSINT/0.1 (+public-profile-check)"

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
        status, body = response.status_code, response.text[:200_000].lower()
        if status == 200 and not any(m in body for m in provider.not_found_markers):
            state, confidence, detail = "candidate", "low", "Public profile page responded. Manually verify it belongs to the intended subject."
        elif status == 404:
            state, confidence, detail = "not_found", "none", "Provider returned HTTP 404."
        elif status in (401, 403, 429):
            state, confidence, detail = "inconclusive", "none", f"Provider restricted or rate-limited the request (HTTP {status})."
        elif 300 <= status < 400:
            state, confidence, detail = "inconclusive", "none", f"Redirect received (HTTP {status}); not followed automatically."
        else:
            state, confidence, detail = "inconclusive", "none", f"Unexpected provider response (HTTP {status})."
        return {"provider": provider.name, "profile_url": url, "status": state, "http_status": status, "confidence": confidence, "detail": detail, "checked_at": checked}
    except (httpx.TimeoutException, httpx.NetworkError):
        return {"provider": provider.name, "profile_url": url, "status": "inconclusive", "http_status": None, "confidence": "none", "detail": "Network timeout or connection error.", "checked_at": checked}

async def search_username(username: str) -> list[dict]:
    username = validate_username(username)
    async with httpx.AsyncClient(timeout=httpx.Timeout(6.0, connect=3.0), limits=httpx.Limits(max_connections=5), headers={"User-Agent": USER_AGENT}) as client:
        return await asyncio.gather(*(_check(client, p, username) for p in PROVIDERS))
