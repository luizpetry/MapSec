"""DNS enumeration plugin."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import httpx

from mapsec.core.plugin import BasePlugin, register_plugin

# Common subdomains for brute force
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "dns",
    "dns1",
    "dns2",
    "mx",
    "mx1",
    "mx2",
    "webmail",
    "email",
    "cloud",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "vpn",
    "remote",
    "blog",
    "shop",
    "store",
    "app",
    "cdn",
    "media",
    "static",
    "assets",
    "img",
    "images",
    "video",
    "news",
    "forum",
    "community",
    "support",
    "help",
    "docs",
    "wiki",
    "status",
    "monitor",
    "grafana",
    "prometheus",
    "jenkins",
    "gitlab",
    "github",
    "bitbucket",
    "jira",
    "confluence",
    "slack",
    "teams",
    "zoom",
    "meet",
    "calendar",
    "crm",
    "erp",
    "hr",
    "finance",
    "accounting",
    "billing",
    "payments",
    "checkout",
    "cart",
    "orders",
    "tracking",
    "shipping",
    "warehouse",
    "inventory",
    "supply",
    "logistics",
    "partner",
    "vendor",
    "supplier",
    "client",
    "customer",
    "user",
    "login",
    "auth",
    "sso",
    "oauth",
    "ldap",
    "active",
    "directory",
    "proxy",
    "gateway",
    "load",
    "balancer",
    "cache",
    "redis",
    "memcached",
    "database",
    "db",
    "sql",
    "mysql",
    "postgres",
    "mongo",
    "elastic",
    "kibana",
    "logstash",
    "splunk",
    "sumo",
    "datadog",
    "newrelic",
    "sentry",
]


@register_plugin
class DnsPlugin(BasePlugin):
    """DNS resolution and subdomain enumeration plugin."""

    name = "dns"
    description = "DNS record lookup and subdomain enumeration"

    async def run(self, target: str) -> dict[str, Any]:
        """Execute DNS enumeration."""
        # Resolve DNS records
        records = await self._resolve_records(target)

        # Subdomain brute force
        subdomains = await self._brute_force_subdomains(target)

        return {
            "domain": target,
            "records": records,
            "subdomains": subdomains,
            "total_subdomains": len(subdomains),
        }

    async def _resolve_records(self, domain: str) -> dict[str, Any]:
        """Resolve various DNS record types."""
        records: dict[str, Any] = {}

        # A records
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None, socket.AF_INET)
            a_records = list(set(r[4][0] for r in result))
            records["A"] = a_records
        except socket.gaierror:
            records["A"] = []

        # AAAA records
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None, socket.AF_INET6)
            aaaa_records = list(set(r[4][0] for r in result))
            records["AAAA"] = aaaa_records
        except socket.gaierror:
            records["AAAA"] = []

        # Try to get MX, NS, TXT via DNS API (if available)
        # For MVP, we'll use a simple DNS lookup service
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Using Google's DNS-over-HTTPS for MX records
                resp = await client.get(
                    f"https://dns.google/resolve?name={domain}&type=MX"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    mx_records = [
                        {
                            "exchange": ans.get("data", ""),
                            "priority": ans.get("TTL", 0),
                        }
                        for ans in data.get("Answer", [])
                        if ans.get("type") == 15
                    ]
                    records["MX"] = mx_records
        except Exception:
            records["MX"] = []

        return records

    async def _brute_force_subdomains(self, domain: str) -> list[dict[str, str]]:
        """Brute force common subdomains."""
        found = []

        async def check_subdomain(subdomain: str) -> dict[str, str] | None:
            fqdn = f"{subdomain}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                result = await loop.getaddrinfo(fqdn, None, socket.AF_INET)
                ips = list(set(r[4][0] for r in result))
                return {"subdomain": fqdn, "ips": ips}
            except socket.gaierror:
                return None

        # Run checks in parallel (batched to avoid overwhelming DNS)
        batch_size = 20
        for i in range(0, len(COMMON_SUBDOMAINS), batch_size):
            batch = COMMON_SUBDOMAINS[i : i + batch_size]
            tasks = [check_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result is not None:
                    found.append(result)

        return found

    def validate_target(self, target: str) -> bool:
        """Validate target is a valid domain."""
        # Simple domain validation
        parts = target.split(".")
        return len(parts) >= 2 and all(part.isalnum() or "-" in part for part in parts)
