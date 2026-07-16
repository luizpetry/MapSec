"""Port scan plugin — pure Python, no external tools required."""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# Common ports with service names
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "sun-answerbook",
    27017: "mongodb",
}


@register_plugin
class NmapPlugin(BasePlugin):
    """Port scanning plugin using pure Python sockets."""

    name = "nmap"
    description = "Port scan and service detection (pure Python)"

    async def run(self, target: str) -> dict[str, Any]:
        """Execute port scan against target."""
        # Resolve target to IP
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET)
            ip = infos[0][4][0] if infos else target
        except socket.gaierror:
            ip = target

        # Scan common ports
        open_ports = await self._scan_ports(ip, list(COMMON_PORTS.keys()))

        # Build results
        hosts = []
        ports = []
        for port_num in sorted(open_ports):
            service = COMMON_PORTS.get(port_num, "unknown")
            ports.append({
                "port": port_num,
                "protocol": "tcp",
                "state": "open",
                "service": {
                    "name": service,
                    "product": "",
                    "version": "",
                    "extra_info": "",
                },
            })

        hosts.append({
            "ip": ip,
            "hostname": target if target != ip else "",
            "ports": ports,
        })

        return {
            "hosts": hosts,
            "scan_info": {
                "type": "tcp",
                "protocol": "tcp",
                "num_services": str(len(ports)),
            },
            "total_hosts": len(hosts),
        }

    async def _scan_ports(self, ip: str, ports: list[int]) -> list[int]:
        """Scan a list of ports asynchronously."""
        open_ports = []

        async def check_port(port: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.5,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        # Scan in batches of 50 for performance
        batch_size = 50
        for i in range(0, len(ports), batch_size):
            batch = ports[i : i + batch_size]
            tasks = [check_port(p) for p in batch]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r is not None:
                    open_ports.append(r)

        return open_ports

    def validate_target(self, target: str) -> bool:
        """Validate target is a valid IP or hostname."""
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
        return bool(re.match(ipv4_pattern, target) or re.match(hostname_pattern, target))
