"""CVE lookup plugin — uses NVD API (auto-detects software from nmap/banner results)."""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# NVD API configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 6  # seconds between requests (no API key)
MAX_CVES_PER_SOFTWARE = 20

# Regex patterns to extract product/version from banner strings
# Order matters: named products first (more specific), then generic patterns
BANNER_PRODUCT_PATTERNS: list[re.Pattern] = [
    # Named products — match specific known software names first
    re.compile(
        r"(?P<product>OpenSSH|Apache|nginx|OpenSSL|ProFTPD|vsftpd|PostgreSQL|MySQL|MariaDB|Redis|Tomcat|IIS|PHP|Python|Node\.js)"
        r"[\/\s_-]+v?(?P<version>[\d.]+[a-z\d]*)",
        re.IGNORECASE,
    ),
    # product/version with slash separator (e.g., Apache/2.4.49)
    re.compile(r"(?P<product>[a-zA-Z][a-zA-Z0-9]+)/(?P<version>[\d.]+[a-z\d]*)"),
    # product-version or product_version (e.g., OpenSSH_8.2p1)
    re.compile(r"(?P<product>[a-zA-Z][a-zA-Z0-9]+)[_-](?P<version>[\d.]+[a-z\d]*)"),
]


# Map common banner product names to real NVD product names
PRODUCT_ALIASES: dict[str, str] = {
    "coyote": "tomcat",
    "tomcat": "tomcat",
    "httpserver": "http_server",
    "openresty": "openresty",
    "lighttpd": "lighttpd",
    "iis": "internet_information_server",
    "microsoft-iis": "internet_information_server",
    "openssh": "openssh",
    "proftpd": "proftpd",
    "vsftpd": "vsftpd",
    "pure-ftpd": "pure-ftpd",
    "filezilla": "filezilla_server",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "python": "python",
    "php": "php",
    "node": "node.js",
    "openssl": "openssl",
    "nginx": "nginx",
    "cisco": "cisco_ios",
}


def _normalize_product(product: str) -> str:
    """Normalize product name for CPE matching (lowercase, strip common prefixes)."""
    name = product.strip().lower()
    # Remove common prefixes for better CPE matching
    for prefix in ("apache ", "apache_", "apache/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    # Normalize underscores vs dots
    name = name.replace("_", "").replace("-", "").replace(".", "")
    # Apply alias mapping
    name = PRODUCT_ALIASES.get(name, name)
    return name


def _normalize_version(version: str) -> str:
    """Normalize version string for CPE matching."""
    return version.strip().lower()


def _extract_from_nmap(context: dict) -> list[dict[str, str]]:
    """Extract software entries from nmap context."""
    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    hosts = context.get("nmap", {}).get("hosts", [])
    for host in hosts:
        ports = host.get("ports", [])
        for port_entry in ports:
            service = port_entry.get("service", {})
            product = (service.get("product") or "").strip()
            version = (service.get("version") or "").strip()
            name = (service.get("name") or "").strip()

            if product and version:
                key = (_normalize_product(product), _normalize_version(version))
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "product": product,
                        "version": version,
                        "source": "nmap",
                    })
            elif name and version:
                key = (_normalize_product(name), _normalize_version(version))
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "product": name,
                        "version": version,
                        "source": "nmap",
                    })

    return results


def _extract_from_banner(context: dict) -> list[dict[str, str]]:
    """Extract software entries from banner grabbing context."""
    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    banners = context.get("banner", {}).get("banners", [])
    for entry in banners:
        banner_text = entry.get("banner", "")
        if not banner_text:
            continue

        for pattern in BANNER_PRODUCT_PATTERNS:
            match = pattern.search(banner_text)
            if match:
                product = match.group("product").strip()
                version = match.group("version").strip()
                if product and version:
                    key = (_normalize_product(product), _normalize_version(version))
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "product": product,
                            "version": version,
                            "source": "banner",
                        })
                    break  # first match wins per banner

    return results


def _merge_software_entries(
    nmap_entries: list[dict[str, str]],
    banner_entries: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Merge and deduplicate software entries from all sources."""
    seen: set[tuple[str, str]] = set()
    merged: list[dict[str, str]] = []

    for entry in nmap_entries + banner_entries:
        key = (
            _normalize_product(entry["product"]),
            _normalize_version(entry["version"]),
        )
        if key not in seen:
            seen.add(key)
            merged.append(entry)

    return merged


def _score_to_severity(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _build_cpe_search(product: str, version: str) -> str:
    """Build a CPE 2.3 URI for virtualMatchString search."""
    cpe_product = re.sub(r"[^a-z0-9.*-]", "", _normalize_product(product))
    cpe_version = re.sub(r"[^a-z0-9.*-]", "", _normalize_version(version))
    if not cpe_product:
        cpe_product = "*"
    if not cpe_version:
        cpe_version = "*"
    return f"cpe:2.3:a:{cpe_product}:{cpe_version}:*:*:*:*:*:*:*"


@register_plugin
class CveLookupPlugin(BasePlugin):
    """CVE vulnerability lookup via NVD API — auto-detects from nmap/banner results."""

    name = "cve"
    description = "CVE vulnerability lookup via NVD API (auto-detects from nmap/banner results)"

    def __init__(self) -> None:
        self.api_key = ""  # Optional: set NVD_API_KEY env var for higher rate limits

    async def run(self, target: str, context: dict | None = None) -> dict[str, Any]:
        """Look up CVEs for software detected on the target.

        Extracts product/version information from other plugin results
        (nmap, banner) provided via the context dict, then queries the
        NVD API for known vulnerabilities.
        """
        if not context:
            return {
                "target": target,
                "software_found": [],
                "cves": [],
                "summary": {
                    "total_cves": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
                "info": "No software versions detected for CVE lookup",
            }

        # Extract software from all available sources
        nmap_entries = _extract_from_nmap(context)
        banner_entries = _extract_from_banner(context)
        software_list = _merge_software_entries(nmap_entries, banner_entries)

        if not software_list:
            return {
                "target": target,
                "software_found": [],
                "cves": [],
                "summary": {
                    "total_cves": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
                "info": "No software versions detected for CVE lookup",
            }

        # Query NVD API for each software entry
        all_cves: list[dict[str, Any]] = []
        for sw in software_list:
            cves = await self._query_nvd(sw["product"], sw["version"], sw["source"])
            all_cves.extend(cves)

        # Build summary statistics
        summary: dict[str, int] = {
            "total_cves": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for cve in all_cves:
            summary["total_cves"] += 1
            severity = cve.get("severity", "")
            if severity == "CRITICAL":
                summary["critical"] += 1
            elif severity == "HIGH":
                summary["high"] += 1
            elif severity == "MEDIUM":
                summary["medium"] += 1
            elif severity == "LOW":
                summary["low"] += 1

        return {
            "target": target,
            "software_found": software_list,
            "cves": all_cves,
            "summary": summary,
        }

    async def _query_nvd(
        self,
        product: str,
        version: str,
        source: str,
    ) -> list[dict[str, Any]]:
        """Query the NVD API for CVEs affecting a specific product/version.

        Uses keywordSearch which is more flexible than CPE matching —
        searches CVE descriptions for the product name and version.
        Applies product alias mapping for better NVD matching.
        """
        # Apply alias mapping for better NVD keyword matching
        mapped_product = PRODUCT_ALIASES.get(product.strip().lower(), product)

        # Strip common suffixes for better keyword matching
        clean_product = mapped_product
        for suffix in (" httpd", " server", " daemon", " ssh"):
            if clean_product.lower().endswith(suffix):
                clean_product = clean_product[: -len(suffix)]
                break

        keyword = f"{clean_product} {version}"
        url = f"{NVD_API_URL}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={MAX_CVES_PER_SOFTWARE}"

        try:
            result = await asyncio.to_thread(self._fetch_nvd, url)

            # Add delay for rate limiting even on success
            await asyncio.sleep(NVD_RATE_LIMIT_DELAY)

            data = json.loads(result)
            vulns = data.get("vulnerabilities", [])

            parsed: list[dict[str, Any]] = []
            for vuln in vulns[:MAX_CVES_PER_SOFTWARE]:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract description (English preferred)
                description = ""
                descriptions = cve_data.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                if not description and descriptions:
                    description = descriptions[0].get("value", "")

                # Extract CVSS score and severity
                score = 0.0
                severity = "UNKNOWN"
                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    cvss_data = cvss_v31[0].get("cvssData", {})
                    score = float(cvss_data.get("baseScore", 0))
                    severity = _score_to_severity(score)
                else:
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    if cvss_v30:
                        cvss_data = cvss_v30[0].get("cvssData", {})
                        score = float(cvss_data.get("baseScore", 0))
                        severity = _score_to_severity(score)
                    else:
                        cvss_v2 = metrics.get("cvssMetricV2", [])
                        if cvss_v2:
                            cvss_data = cvss_v2[0].get("cvssData", {})
                            score = float(cvss_data.get("baseScore", 0))
                            severity = _score_to_severity(score)

                parsed.append({
                    "id": cve_id,
                    "product": product,
                    "version": version,
                    "description": description,
                    "severity": severity,
                    "score": score,
                    "source": source,
                })

            return parsed

        except urllib.error.HTTPError as e:
            # Rate-limited or no results — still respect delay
            await asyncio.sleep(NVD_RATE_LIMIT_DELAY)
            if e.code == 403:
                return [
                    {
                        "id": "",
                        "product": product,
                        "version": version,
                        "description": f"NVD rate limited (HTTP 403). Consider setting NVD_API_KEY or reducing scan frequency.",
                        "severity": "UNKNOWN",
                        "score": 0.0,
                        "source": source,
                        "error": "rate_limited",
                    },
                ]
            elif e.code == 404:
                return []  # No CVEs found for this product/version
            else:
                return [
                    {
                        "id": "",
                        "product": product,
                        "version": version,
                        "description": f"NVD API returned HTTP {e.code}",
                        "severity": "UNKNOWN",
                        "score": 0.0,
                        "source": source,
                        "error": f"http_{e.code}",
                    },
                ]
        except Exception as e:
            await asyncio.sleep(NVD_RATE_LIMIT_DELAY)
            return [
                {
                    "id": "",
                    "product": product,
                    "version": version,
                    "description": f"NVD query error: {e}",
                    "severity": "UNKNOWN",
                    "score": 0.0,
                    "source": source,
                    "error": str(e),
                },
            ]

    def _fetch_nvd(self, url: str) -> str:
        """Fetch NVD API response (blocking, runs in executor)."""
        headers = {
            "User-Agent": "Mapsec/0.1.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()

    def validate_target(self, target: str) -> bool:
        """CVE lookup is context-dependent — accepts any target for pipeline use."""
        return True
