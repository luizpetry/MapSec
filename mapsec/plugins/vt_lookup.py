"""VirusTotal lookup plugin — uses only Python standard library."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

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
                "error": "VT_API_KEY environment variable not set. Get a free key at https://www.virustotal.com/gui/join-us",
                "target": target,
            }

        if self._is_ip(target):
            return await self._lookup_ip(target)
        else:
            return await self._lookup_domain(target)

    async def _lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up an IP address."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        return await self._api_request(url, "ip", ip)

    async def _lookup_domain(self, domain: str) -> dict[str, Any]:
        """Look up a domain."""
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        return await self._api_request(url, "domain", domain)

    async def _api_request(self, url: str, type_name: str, target: str) -> dict[str, Any]:
        """Make a VT API request using urllib (no httpx needed)."""
        import asyncio

        try:
            result = await asyncio.to_thread(self._fetch_url, url)
            data = json.loads(result)
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            return {
                "type": type_name,
                "target": target,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total_votes": attrs.get("total_votes", {}),
                "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date", ""),
                "categories": attrs.get("categories", {}),
            }
        except urllib.error.HTTPError as e:
            return {
                "type": type_name,
                "target": target,
                "error": f"API returned status {e.code}",
            }
        except Exception as e:
            return {
                "type": type_name,
                "target": target,
                "error": str(e),
            }

    def _fetch_url(self, url: str) -> str:
        """Fetch URL content (blocking, runs in executor)."""
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "User-Agent": "Mapsec/0.1.0",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        parts = target.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def validate_target(self, target: str) -> bool:
        """VT can look up both IPs and domains."""
        return True
