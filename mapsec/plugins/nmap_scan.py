"""Nmap port scan plugin."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin


@register_plugin
class NmapPlugin(BasePlugin):
    """Port scanning plugin using nmap."""

    name = "nmap"
    description = "Port scan and service detection via nmap"

    async def run(self, target: str) -> dict[str, Any]:
        """Execute nmap scan and parse XML output."""
        cmd = [
            "nmap",
            "-sV",  # Service/version detection
            "-oX",
            "-",  # Output XML to stdout
            "--open",  # Show only open ports
            target,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                raise RuntimeError(f"nmap failed: {stderr.decode()}")

            return self._parse_xml(stdout.decode())
        except FileNotFoundError:
            raise RuntimeError("nmap is not installed or not in PATH")

    def _parse_xml(self, xml_output: str) -> dict[str, Any]:
        """Parse nmap XML output into structured data."""
        root = ET.fromstring(xml_output)

        hosts = []
        for host in root.findall(".//host"):
            # Get IP address
            addr_elem = host.find("address[@addrtype='ipv4']")
            ip = addr_elem.get("addr", "") if addr_elem is not None else ""

            # Get hostname
            hostname_elem = host.find(".//hostname")
            hostname = hostname_elem.get("name", "") if hostname_elem is not None else ""

            # Get ports
            ports = []
            for port_elem in host.findall(".//port"):
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""

                service_elem = port_elem.find("service")
                service_info = {}
                if service_elem is not None:
                    service_info = {
                        "name": service_elem.get("name", ""),
                        "product": service_elem.get("product", ""),
                        "version": service_elem.get("version", ""),
                        "extra_info": service_elem.get("extrainfo", ""),
                    }

                ports.append({
                    "port": int(port_id) if port_id.isdigit() else port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_info,
                })

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports,
            })

        # Get scan info
        scan_info = {}
        scan_info_elem = root.find("scaninfo")
        if scan_info_elem is not None:
            scan_info = {
                "type": scan_info_elem.get("type", ""),
                "protocol": scan_info_elem.get("protocol", ""),
                "num_services": scan_info_elem.get("numservices", ""),
            }

        return {
            "hosts": hosts,
            "scan_info": scan_info,
            "total_hosts": len(hosts),
        }

    def validate_target(self, target: str) -> bool:
        """Validate target is a valid IP or hostname."""
        # Simple IPv4 pattern
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        # Simple hostname pattern
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"

        return bool(re.match(ipv4_pattern, target) or re.match(hostname_pattern, target))
