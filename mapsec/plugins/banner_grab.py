"""Banner grabbing plugin — pure Python, no external tools required."""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# Ports to probe for banners with their service names
BANNER_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    993: "imaps",
    995: "pop3s",
    8080: "http",
    8443: "https",
}

# Ports that require an HTTP request to elicit a banner
HTTP_PORTS: set[int] = {80, 443, 8080, 8443}

# Timeout in seconds for each connection attempt
BANNER_READ_TIMEOUT: float = 3.0

# Maximum banner string length to store
MAX_BANNER_LENGTH: int = 200


@register_plugin
class BannerGrabPlugin(BasePlugin):
    """Service banner grabbing from open ports."""

    name = "banner"
    description = "Service banner grabbing from open ports"

    async def run(self, target: str) -> dict[str, Any]:
        """Execute banner grabbing against target."""
        # Resolve target to IP (same pattern as nmap_scan.py)
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET)
            ip: str = infos[0][4][0] if infos else target
        except socket.gaierror:
            ip = target

        # Grab banners from all configured ports
        banners: list[dict[str, Any]] = []
        tasks = [
            self._grab_banner(ip, target, port, service)
            for port, service in BANNER_PORTS.items()
        ]
        results = await asyncio.gather(*tasks)

        for banner in results:
            if banner is not None:
                banners.append(banner)

        # Sort by port number for consistent output
        banners.sort(key=lambda b: b["port"])

        return {
            "target": target if target != ip else ip,
            "ip": ip,
            "banners": banners,
            "total_banners": len(banners),
        }

    async def _grab_banner(
        self,
        ip: str,
        original_target: str,
        port: int,
        service: str,
    ) -> dict[str, Any] | None:
        """Connect to a port and read its service banner.

        Args:
            ip: Resolved IP address to connect to.
            original_target: Original user-supplied target (used for HTTP Host header).
            port: Target port number.
            service: Service name for the port.

        Returns:
            Banner result dict or None if the port is closed / unresponsive.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=BANNER_READ_TIMEOUT,
            )
        except (
            asyncio.TimeoutError,
            ConnectionRefusedError,
            ConnectionResetError,
            ConnectionAbortedError,
            OSError,
        ):
            return None

        result: dict[str, Any] = {
            "port": port,
            "service": service,
            "protocol": service,
        }

        try:
            if port in HTTP_PORTS:
                await self._grab_http_banner(reader, writer, original_target, result)
            else:
                await self._grab_raw_banner(reader, writer, result)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            # Non-fatal: banner read failed after connect
            pass
        finally:
            writer.close()
            await writer.wait_closed()

        return result if "banner" in result else None

    async def _grab_http_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        result: dict[str, Any],
    ) -> None:
        """Send a minimal HTTP HEAD request and parse response headers.

        Populates result['banner'] and result['headers'].
        """
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; Mapsec/0.1.0)\r\n"
            f"\r\n"
        )
        writer.write(request.encode("utf-8"))
        await writer.drain()

        response_data = await asyncio.wait_for(
            reader.read(4096),
            timeout=BANNER_READ_TIMEOUT,
        )
        decoded = response_data.decode("utf-8", errors="replace")

        headers = self._parse_http_headers(decoded)
        result["headers"] = headers

        # Primary banner from Server header
        banner_parts: list[str] = []
        if "Server" in headers:
            banner_parts.append(headers["Server"])
        if "X-Powered-By" in headers:
            banner_parts.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if "X-AspNet-Version" in headers:
            banner_parts.append(f"ASP.NET: {headers['X-AspNet-Version']}")

        if banner_parts:
            banner_text = " / ".join(banner_parts)
            result["banner"] = banner_text[:MAX_BANNER_LENGTH]

    async def _grab_raw_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        result: dict[str, Any],
    ) -> None:
        """Read raw banner data sent by non-HTTP services on connect."""
        data = await asyncio.wait_for(
            reader.read(1024),
            timeout=BANNER_READ_TIMEOUT,
        )
        if data:
            banner_text = data.decode("utf-8", errors="replace")
            banner_text = self._clean_banner(banner_text)
            if banner_text:
                result["banner"] = banner_text[:MAX_BANNER_LENGTH]

    @staticmethod
    def _parse_http_headers(raw_response: str) -> dict[str, str]:
        """Extract relevant HTTP response headers into a dictionary.

        Only headers of interest for fingerprinting are included.
        """
        headers: dict[str, str] = {}
        lines = raw_response.split("\r\n")

        # Skip the status line (first line), parse subsequent headers
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            key_lower = key.lower()
            if key_lower in (
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-server",
            ):
                headers[key] = value

        return headers

    @staticmethod
    def _clean_banner(raw: str) -> str:
        """Remove control characters and normalize whitespace."""
        # Strip null bytes and control characters (keep tabs, newlines)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
        # Collapse consecutive whitespace into single spaces
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()

    def validate_target(self, target: str) -> bool:
        """Validate target is a valid IP or hostname (same pattern as nmap)."""
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        hostname_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
        )
        return bool(
            re.match(ipv4_pattern, target) or re.match(hostname_pattern, target)
        )
