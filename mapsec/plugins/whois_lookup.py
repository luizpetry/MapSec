"""WHOIS lookup plugin — pure Python asyncio implementation."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# WHOIS server map by TLD
TLD_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
}

# Default WHOIS servers
IP_WHOIS_SERVER = "whois.arin.net"
DEFAULT_WHOIS_SERVER = "whois.iana.org"


# ---------------------------------------------------------------------------
# Helper: extract a single field value by matching line prefixes
# ---------------------------------------------------------------------------

def _extract_field(data: str, *patterns: str) -> str:
    """Return the value from the first line that starts with *any* *pattern*.

    Matching is case‑insensitive.  The line is split on ``:``  and the
    remainder is stripped.
    """
    for line in data.splitlines():
        stripped = line.strip()
        for pat in patterns:
            if stripped.lower().startswith(pat.lower()):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
    return ""


# ===================================================================
# Plugin
# ===================================================================

@register_plugin
class WhoisPlugin(BasePlugin):
    """WHOIS lookup for domain and IP registration info."""

    name = "whois"
    description = "WHOIS lookup for domain and IP registration info"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, target: str) -> dict[str, Any]:
        """Execute WHOIS lookup against *target* (domain or IPv4)."""
        # 1. Determine target type and select the correct WHOIS server
        if self._is_ip(target):
            target_type = "ip"
            server = IP_WHOIS_SERVER
            query = f"n + {target}"
        else:
            target_type = "domain"
            tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
            server = TLD_SERVERS.get(tld, DEFAULT_WHOIS_SERVER)
            query = target

        # 2. Perform the WHOIS query
        raw_data = await self._whois_query(server, query)

        # 3. Parse structured fields from the raw response
        registrar = _extract_field(
            raw_data,
            "registrar:",
            "registrar name:",
        )
        creation_date = _extract_field(
            raw_data,
            "creation date:",
            "created:",
        )
        expiration_date = _extract_field(
            raw_data,
            "registry expiry date:",
            "expiration date:",
            "expiry date:",
            "expire:",
        )
        name_servers = self._extract_name_servers(raw_data)
        registrant_org = _extract_field(
            raw_data,
            "registrant organization:",
            "org-name:",
            "orgname:",
            "person:",
        )
        registrant_country = _extract_field(
            raw_data,
            "registrant country:",
            "country:",
        )

        return {
            "target": target,
            "type": target_type,
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": name_servers,
            "registrant": {
                "org": registrant_org,
                "country": registrant_country,
            },
            "raw_length": len(raw_data),
        }

    def validate_target(self, target: str) -> bool:
        """Accept domains (at least two labels) and IPv4 addresses."""
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        domain_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$"
        )
        return bool(re.match(ipv4_pattern, target) or re.match(domain_pattern, target))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _whois_query(self, server: str, query: str) -> str:
        """Connect to *server*:43, send *query*, and return the full response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 43),
                timeout=10.0,
            )

            # Send the query line (WHOIS protocol uses CRLF)
            writer.write(f"{query}\r\n".encode("ascii"))
            await writer.drain()

            # Read all response data
            raw = await asyncio.wait_for(
                self._read_all(reader),
                timeout=10.0,
            )

            writer.close()
            await writer.wait_closed()

            return raw.decode("ascii", errors="replace")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            # Return a sentinel so callers can still produce an empty result
            # without raising.
            return f"# ERROR: {exc}"

    @staticmethod
    async def _read_all(reader: asyncio.StreamReader) -> bytes:
        """Read until EOF from an ``asyncio.StreamReader``."""
        chunks: list[bytes] = []
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _extract_name_servers(data: str) -> list[str]:
        """Collect all ``Name Server:`` (or ``nserver:``) entries."""
        servers: set[str] = set()
        for line in data.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("name server:") or lower.startswith("nserver:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    ns = parts[1].strip().lower()
                    if ns:
                        servers.add(ns)
        return sorted(servers)

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Return ``True`` when *target* is a valid IPv4 address."""
        parts = target.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
