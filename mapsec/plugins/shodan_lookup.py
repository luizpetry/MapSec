"""Shodan IoT/device lookup plugin — uses only Python standard library."""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import urllib.error
import urllib.request
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@register_plugin
class ShodanPlugin(BasePlugin):
    """Shodan IoT / device search on exposed services."""

    name = "shodan"
    description = "Shodan IoT/device search on exposed services"

    def __init__(self) -> None:
        self.api_key = os.environ.get("SHODAN_API_KEY", "")

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    async def run(self, target: str) -> dict[str, Any]:
        """Look up *target* on Shodan (IP or domain)."""
        if not self.api_key:
            return {
                "error": (
                    "SHODAN_API_KEY environment variable not set. "
                    "Get a free key at https://account.shodan.io/register"
                ),
                "target": target,
            }

        if self._is_ip(target):
            return await self._lookup_host(target)
        else:
            return await self._resolve_and_lookup(target)

    def validate_target(self, target: str) -> bool:
        """Accept IPs or domains (at least two dotted parts)."""
        if _IP_RE.match(target):
            return True
        parts = target.strip().split(".")
        return len(parts) >= 2 and all(len(p) > 0 for p in parts)

    # ──────────────────────────────────────────────
    #  Shodan host lookup (core)
    # ──────────────────────────────────────────────

    async def _lookup_host(self, ip: str) -> dict[str, Any]:
        """Fetch host info from the Shodan Host API."""
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"

        try:
            raw = await asyncio.to_thread(self._fetch_url, url)
            data = json.loads(raw)
            return self._parse_host(data, ip)
        except urllib.error.HTTPError as e:
            return self._handle_http_error(e, ip)
        except Exception as e:
            return {"target": ip, "error": str(e)}

    # ──────────────────────────────────────────────
    #  Domain resolution → host lookup
    # ──────────────────────────────────────────────

    async def _resolve_and_lookup(self, domain: str) -> dict[str, Any]:
        """Resolve *domain* to an IPv4 address, then look it up on Shodan."""
        try:
            result = await asyncio.to_thread(self._resolve, domain)
            if result is None:
                return {
                    "target": domain,
                    "error": f"Could not resolve domain '{domain}' to an IP address",
                }
            ip = result
        except Exception as e:
            return {"target": domain, "error": f"DNS resolution failed: {e}"}

        host_data = await self._lookup_host(ip)
        # Copy the domain back as the original target
        host_data["target"] = domain
        return host_data

    @staticmethod
    def _resolve(domain: str) -> str | None:
        """Resolve a domain name to an IPv4 address (blocking)."""
        try:
            addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
            if addrs:
                return addrs[0][4][0]
            return None
        except (socket.gaierror, OSError):
            return None

    # ──────────────────────────────────────────────
    #  Response parsing
    # ──────────────────────────────────────────────

    @staticmethod
    def _parse_host(data: dict[str, Any], ip: str) -> dict[str, Any]:
        """Transform raw Shodan JSON response into the canonical output dict."""
        vulns_raw = data.get("vulns") or {}
        vulns_list: list[str] = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else []

        services_raw = data.get("data") or []
        services: list[dict[str, Any]] = []
        for entry in services_raw:
            svc: dict[str, Any] = {"port": entry.get("port")}
            product = entry.get("product")
            if product:
                svc["product"] = product
            version = entry.get("version")
            if version:
                svc["version"] = version
            transport = entry.get("transport", "tcp")
            if transport:
                svc["transport"] = transport
            services.append(svc)

        return {
            "target": ip,
            "ip": data.get("ip_str", ip),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "os": data.get("os", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": vulns_list,
            "services": services,
        }

    @staticmethod
    def _handle_http_error(err: urllib.error.HTTPError, target: str) -> dict[str, Any]:
        """Mapeia códigos HTTP para mensagens significativas."""
        code = err.code
        if code == 401:
            msg = "Invalid API key. Get a valid key at https://account.shodan.io/register"
        elif code == 404:
            msg = f"Host '{target}' not found in Shodan database"
        elif code == 429:
            msg = "Rate limit exceeded. Please wait and retry later."
        else:
            msg = f"Shodan API returned HTTP {code}"
        return {"target": target, "error": msg}

    # ──────────────────────────────────────────────
    #  HTTP helper
    # ──────────────────────────────────────────────

    @staticmethod
    def _fetch_url(url: str) -> str:
        """Fetch URL content (blocking — runs in executor thread)."""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mapsec/0.1.0",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")

    # ──────────────────────────────────────────────
    #  IP detection
    # ──────────────────────────────────────────────

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Return True if *target* is an IPv4 address."""
        return bool(_IP_RE.match(target))
