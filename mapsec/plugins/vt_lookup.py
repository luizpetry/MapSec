"""VirusTotal lookup plugin."""

from __future__ import annotations

import os
from typing import Any

import httpx

from mapsec.core.plugin import BasePlugin, register_plugin


@register_plugin
class VirusTotalPlugin(BasePlugin):
    """VirusTotal intelligence lookup plugin."""

    name = "vt"
    description = "VirusTotal threat intelligence lookup"

    def __init__(self) -> None:
        self.api_key = os.environ.get("VT_API_KEY", "")

    async def run(self, target: str) -> dict[str, Any]:
        """Look up target on VirusTotal."""
        if not self.api_key:
            return {
                "error": "VT_API_KEY environment variable not set",
                "target": target,
            }

        # Determine if target is IP or domain
        if self._is_ip(target):
            return await self._lookup_ip(target)
        else:
            return await self._lookup_domain(target)

    async def _lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up an IP address."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
            )

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "type": "ip",
                    "target": ip,
                    "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
                    "total_votes": attrs.get("total_votes", {}),
                    "asn": attrs.get("asn", ""),
                    "as_owner": attrs.get("as_owner", ""),
                    "country": attrs.get("country", ""),
                    "network": attrs.get("network", ""),
                }
            else:
                return {
                    "type": "ip",
                    "target": ip,
                    "error": f"API returned status {resp.status_code}",
                }

    async def _lookup_domain(self, domain: str) -> dict[str, Any]:
        """Look up a domain."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.api_key},
            )

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "type": "domain",
                    "target": domain,
                    "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
                    "total_votes": attrs.get("total_votes", {}),
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                    "categories": attrs.get("categories", {}),
                }
            else:
                return {
                    "type": "domain",
                    "target": domain,
                    "error": f"API returned status {resp.status_code}",
                }

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        parts = target.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def validate_target(self, target: str) -> bool:
        """VT can look up both IPs and domains."""
        return True  # Let the API handle validation
