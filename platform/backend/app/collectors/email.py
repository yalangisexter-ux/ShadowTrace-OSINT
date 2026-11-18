"""Passive email intelligence collector (public sources only)."""
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import httpx

from app.core.contracts import Observation

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class EmailCollector:
    name = "email.passive"
    version = "0.1.0"
    description = "Passive MX lookup, domain correlation, and public Gravatar check"

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout

    @staticmethod
    def normalize_target(value: str) -> str:
        target = value.strip().lower()
        if not EMAIL_RE.fullmatch(target):
            raise ValueError("Provide a valid email address.")
        local, _, domain = target.partition("@")
        if not local or not domain or len(target) > 254:
            raise ValueError("Provide a valid email address.")
        return target

    async def collect(self, target: str) -> list[Observation]:
        email = self.normalize_target(target)
        local, _, domain = email.partition("@")
        observations: list[Observation] = [
            Observation(
                entity_type="email",
                value=email,
                relation="investigated_target",
                source="user_input",
                confidence=1.0,
                observed_at=datetime.now(UTC),
            ),
            Observation(
                entity_type="domain",
                value=domain,
                relation="email_domain",
                source="derived",
                confidence=1.0,
            ),
        ]

        # MX records
        try:
            answer = await self.resolver.resolve(domain, "MX", raise_on_no_answer=False)
            if answer.rrset is not None:
                for record in answer:
                    observations.append(
                        Observation(
                            entity_type="dns_record",
                            value=str(record.exchange).rstrip("."),
                            relation="MX",
                            source="system_dns_resolver",
                            confidence=0.95,
                            attributes={"preference": int(record.preference), "note": "MX presence does not prove the mailbox exists."},
                        )
                    )
        except (dns.exception.DNSException, OSError, TimeoutError):
            pass

        # Public Gravatar existence (hash of email)
        try:
            digest = hashlib.md5(email.encode("utf-8")).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.get(gravatar_url, headers={"User-Agent": "ShadowTrace-OSINT/0.1"})
                if response.status_code == 200:
                    observations.append(
                        Observation(
                            entity_type="avatar",
                            value=f"https://www.gravatar.com/avatar/{digest}",
                            relation="gravatar",
                            source="gravatar.com",
                            source_url=f"https://www.gravatar.com/avatar/{digest}",
                            confidence=0.75,
                            attributes={"note": "A Gravatar image is a candidate association, not proof of account ownership."},
                        )
                    )
        except (httpx.HTTPError, ValueError):
            pass

        return observations
