"""DNS enumeration plugin — pure Python, no external tools required."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# Common subdomains for brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "dns", "dns1",
    "dns2", "mx", "mx1", "mx2", "webmail", "email", "cloud", "api", "dev",
    "staging", "test", "admin", "portal", "vpn", "remote", "blog", "shop",
    "store", "app", "cdn", "media", "static", "assets", "img", "images",
    "video", "news", "forum", "community", "support", "help", "docs", "wiki",
    "status", "monitor", "grafana", "prometheus", "jenkins", "gitlab",
    "github", "bitbucket", "jira", "confluence", "crm", "erp", "login",
    "auth", "sso", "proxy", "gateway", "cache", "redis", "database", "db",
    "sql", "mysql", "postgres", "mongo", "elastic", "kibana",
]


@register_plugin
class DnsPlugin(BasePlugin):
    """DNS resolution and subdomain enumeration plugin."""

    name = "dns"
    description = "DNS record lookup and subdomain enumeration"

    async def run(self, target: str) -> dict[str, Any]:
        """Execute DNS enumeration."""
        records = await self._resolve_records(target)
        subdomains = await self._brute_force_subdomains(target)

        return {
            "domain": target,
            "records": records,
            "subdomains": subdomains,
            "total_subdomains": len(subdomains),
        }

    async def _resolve_records(self, domain: str) -> dict[str, Any]:
        """Resolve various DNS record types using pure Python."""
        records: dict[str, Any] = {}

        # A records (IPv4)
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            a_records = list(set(r[4][0] for r in result))
            records["A"] = a_records
        except socket.gaierror:
            records["A"] = []

        # AAAA records (IPv6)
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET6)
            aaaa_records = list(set(r[4][0] for r in result))
            records["AAAA"] = aaaa_records
        except socket.gaierror:
            records["AAAA"] = []

        # MX records via DNS-over-HTTPS (Google)
        records["MX"] = await self._resolve_mx(domain)

        # NS records via DNS-over-HTTPS
        records["NS"] = await self._resolve_ns(domain)

        # TXT records via DNS-over-HTTPS
        records["TXT"] = await self._resolve_txt(domain)

        return records

    async def _resolve_mx(self, domain: str) -> list[dict[str, Any]]:
        """Resolve MX records using Google DNS-over-HTTPS."""
        return await self._dns_query(domain, 15, "MX")

    async def _resolve_ns(self, domain: str) -> list[str]:
        """Resolve NS records using Google DNS-over-HTTPS."""
        results = await self._dns_query(domain, 2, "NS")
        return [r.get("data", "") for r in results]

    async def _resolve_txt(self, domain: str) -> list[str]:
        """Resolve TXT records using Google DNS-over-HTTPS."""
        results = await self._dns_query(domain, 16, "TXT")
        return [r.get("data", "") for r in results]

    async def _dns_query(self, domain: str, qtype: int, type_name: str) -> list[dict[str, Any]]:
        """Query Google DNS-over-HTTPS."""
        import urllib.request
        import json

        url = f"https://dns.google/resolve?name={domain}&type={qtype}"
        try:
            result = await asyncio.to_thread(self._fetch_json, url)
            answers = result.get("Answer", [])
            return [
                {"data": ans.get("data", ""), "ttl": ans.get("TTL", 0)}
                for ans in answers
                if ans.get("type") == qtype
            ]
        except Exception:
            return []

    def _fetch_json(self, url: str) -> dict:
        """Fetch JSON from URL (blocking, runs in executor)."""
        import urllib.request
        import json

        req = urllib.request.Request(url, headers={"User-Agent": "Mapsec/0.1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    async def _brute_force_subdomains(self, domain: str) -> list[dict[str, Any]]:
        """Brute force common subdomains."""
        found = []

        async def check_subdomain(subdomain: str) -> dict[str, Any] | None:
            fqdn = f"{subdomain}.{domain}"
            try:
                result = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                ips = list(set(r[4][0] for r in result))
                return {"subdomain": fqdn, "ips": ips}
            except socket.gaierror:
                return None

        # Run in batches of 30
        batch_size = 30
        for i in range(0, len(COMMON_SUBDOMAINS), batch_size):
            batch = COMMON_SUBDOMAINS[i : i + batch_size]
            tasks = [check_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r is not None:
                    found.append(r)

        return found

    def validate_target(self, target: str) -> bool:
        """Validate target is a valid domain."""
        parts = target.split(".")
        return len(parts) >= 2 and all(part.isalnum() or "-" in part for part in parts)
