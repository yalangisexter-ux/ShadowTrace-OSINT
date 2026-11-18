"""Passive IP intelligence collector (public sources only)."""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import httpx

from app.core.contracts import Observation


class IPCollector:
    name = "ip.passive"
    version = "0.1.0"
    description = "Passive GeoIP, ASN, and network registration lookup"

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    @staticmethod
    def normalize_target(value: str) -> str:
        target = value.strip()
        try:
            addr = ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValueError("Provide a valid IPv4 or IPv6 address.") from exc
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            raise ValueError("Private, loopback, link-local, multicast, and reserved addresses are not accepted.")
        return str(addr)

    async def collect(self, target: str) -> list[Observation]:
        ip = self.normalize_target(target)
        observations: list[Observation] = [
            Observation(
                entity_type="ip",
                value=ip,
                relation="investigated_target",
                source="user_input",
                confidence=1.0,
                observed_at=datetime.now(UTC),
            )
        ]

        # Public GeoIP / network registration via ipwho.is (no API key required for basic use)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.get(
                    f"https://ipwho.is/{ip}",
                    headers={"Accept": "application/json", "User-Agent": "ShadowTrace-OSINT/0.1"},
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success") is not False:
                        if data.get("country"):
                            observations.append(
                                Observation(
                                    entity_type="location",
                                    value=str(data.get("country")),
                                    relation="geoip_country",
                                    source="ipwho.is",
                                    source_url=f"https://ipwho.is/{ip}",
                                    confidence=0.7,
                                    attributes={
                                        "city": data.get("city"),
                                        "region": data.get("region"),
                                        "latitude": data.get("latitude"),
                                        "longitude": data.get("longitude"),
                                        "timezone": (data.get("timezone") or {}).get("id")
                                        if isinstance(data.get("timezone"), dict)
                                        else data.get("timezone"),
                                        "note": "GeoIP is approximate network location, not precise device location.",
                                    },
                                )
                            )
                        connection = data.get("connection") or {}
                        if connection.get("asn"):
                            observations.append(
                                Observation(
                                    entity_type="asn",
                                    value=str(connection.get("asn")),
                                    relation="network_asn",
                                    source="ipwho.is",
                                    source_url=f"https://ipwho.is/{ip}",
                                    confidence=0.85,
                                    attributes={
                                        "org": connection.get("org"),
                                        "isp": connection.get("isp"),
                                        "domain": connection.get("domain"),
                                    },
                                )
                            )
                        if connection.get("isp"):
                            observations.append(
                                Observation(
                                    entity_type="organization",
                                    value=str(connection.get("isp")),
                                    relation="isp",
                                    source="ipwho.is",
                                    source_url=f"https://ipwho.is/{ip}",
                                    confidence=0.8,
                                )
                            )
        except (httpx.HTTPError, ValueError, TypeError):
            pass

        return observations
