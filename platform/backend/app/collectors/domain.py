import asyncio
import ipaddress
import re
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import httpx

from app.core.contracts import Observation


class DomainCollector:
    name = "domain.passive"
    version = "0.1.0"
    description = "Passive DNS and Certificate Transparency collection"

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout

    @staticmethod
    def normalize_target(value: str) -> str:
        target = value.strip().lower().rstrip(".")
        if "://" in target or "/" in target or "@" in target or ":" in target:
            raise ValueError("Provide a bare public domain name, not a URL, email, IP, or host:port.")
        if len(target) > 253 or not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", target):
            raise ValueError("Target must be a valid fully-qualified public DNS name.")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses must use the IP intelligence collector.")
        reserved_suffixes = (".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".onion")
        if target.endswith(reserved_suffixes):
            raise ValueError("Private, reserved, and special-use domains are not accepted.")
        return target

    async def _dns_records(self, domain: str, record_type: str) -> list[Observation]:
        try:
            answer = await self.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer.rrset is None:
                return []
            return [
                Observation(
                    entity_type="dns_record",
                    value=str(record).rstrip("."),
                    relation=record_type,
                    source="system_dns_resolver",
                    confidence=0.95,
                    attributes={"record_type": record_type, "ttl": answer.rrset.ttl},
                )
                for record in answer
            ]
        except (dns.exception.DNSException, OSError, TimeoutError):
            return []

    async def _certificate_transparency(self, domain: str) -> list[Observation]:
        endpoint = "https://crt.sh/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.get(
                    endpoint,
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"Accept": "application/json", "User-Agent": "ShadowTrace-OSINT/0.1"},
                )
                response.raise_for_status()
                rows = response.json()
            found: set[str] = set()
            observations: list[Observation] = []
            for row in rows[:500]:
                for name in str(row.get("name_value", "")).splitlines():
                    candidate = name.strip().lower().lstrip("*.")
                    if candidate == domain or candidate.endswith(f".{domain}"):
                        found.add(candidate)
            for name in sorted(found):
                observations.append(
                    Observation(
                        entity_type="hostname",
                        value=name,
                        relation="certificate_name",
                        source="crt.sh",
                        source_url=f"https://crt.sh/?q=%25.{domain}",
                        confidence=0.9,
                        attributes={"collection": "certificate_transparency"},
                    )
                )
            return observations
        except (httpx.HTTPError, ValueError, TypeError):
            return []

    async def collect(self, target: str) -> list[Observation]:
        domain = self.normalize_target(target)
        record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
        tasks = [self._dns_records(domain, kind) for kind in record_types]
        tasks.append(self._certificate_transparency(domain))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        observations: list[Observation] = []
        for result in results:
            if isinstance(result, list):
                observations.extend(result)
        observations.append(
            Observation(
                entity_type="domain",
                value=domain,
                relation="investigated_target",
                source="user_input",
                confidence=1.0,
                observed_at=datetime.now(UTC),
            )
        )
        return observations
