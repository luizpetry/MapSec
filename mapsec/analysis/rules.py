"""Internal rules engine for security analysis.

Each rule is a function that takes a dict of plugin results (keyed by plugin
name) and returns a list of Finding objects.  Rules must safely handle missing
plugin data via ``.get()`` and early returns.
"""

import datetime
import json
import logging
import ssl
import urllib.request
from typing import Any, Callable

from mapsec.analysis.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HSTS Preload List (cached per session)
# ---------------------------------------------------------------------------

_PRELOAD_CACHE: set[str] | None = None
_PRELOAD_URL = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"


def _is_hsts_preloaded(target: str) -> bool:
    """Check if *target* is in the Chromium HSTS preload list.

    The Chromium preload list uses registered domain names (eTLD+1)
    without the TLD.  For example, ``google.com`` is stored as ``google``.
    This function checks the full target, the parent domain, and the
    registered domain against the cache.

    The list is fetched once per session and cached in memory.  If the
    fetch fails, the function conservatively returns ``False`` (treat as
    not preloaded).
    """
    global _PRELOAD_CACHE  # noqa: PLW0603

    if _PRELOAD_CACHE is None:
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(_PRELOAD_URL, headers={"User-Agent": "Mapsec/0.1.0"})
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                import base64
                raw = resp.read().decode("utf-8")
                decoded = base64.b64decode(raw).decode("utf-8")
                # Strip // comments (the JSON file has comment lines at the top)
                import re as _re
                cleaned = _re.sub(r"//[^\n]*", "", decoded)
                data = json.loads(cleaned)
                entries = data.get("entries", [])
                _PRELOAD_CACHE = set()
                for entry in entries:
                    name = entry.get("name", "")
                    if name:
                        _PRELOAD_CACHE.add(name.lower())
            logger.info("HSTS preload list loaded: %d entries", len(_PRELOAD_CACHE))
        except Exception as e:
            logger.warning("Failed to load HSTS preload list: %s", e)
            _PRELOAD_CACHE = set()  # Empty set = nothing preloaded

    domain = target.lower().strip(".")
    # Check full domain, parent domain, and registered domain (eTLD+1)
    # e.g. for "www.google.com": check "www.google.com", "google.com", "google"
    parts = domain.split(".")
    candidates = [domain]
    for i in range(1, len(parts)):
        candidates.append(".".join(parts[i:]))
    # Also check just the registered name (e.g. "google" for "google.com")
    if len(parts) >= 2:
        candidates.append(parts[-2] if parts[-1] in ("com", "org", "net", "edu", "gov") else parts[-2])

    for candidate in candidates:
        if candidate in _PRELOAD_CACHE:
            return True

    return False

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

# Ports considered dangerous when exposed to the internet
DANGEROUS_PORTS: set[int] = {21, 23, 135, 139, 445, 3389}

# Security headers whose absence is a medium concern
CRITICAL_SECURITY_HEADERS: set[str] = {"X-Frame-Options", "X-Content-Type-Options"}


def _get_hosts_ports(results: dict) -> list[dict]:
    """Extract the flattened list of port dicts from nmap results (if any)."""
    nmap = results.get("nmap", {})
    hosts = nmap.get("hosts", [])
    ports: list[dict] = []
    for host in hosts:
        ports.extend(host.get("ports", []))
    return ports


# ---------------------------------------------------------------------------
# Rule functions (15+)
# ---------------------------------------------------------------------------

def check_open_ports_no_https(results: dict) -> list[Finding]:
    """Open ports found but no HTTPS/TLS service available.

    Severity depends on whether the SSL plugin was also executed:
    - SSL plugin ran and confirmed no TLS → **medium** (confirmed risk)
    - SSL plugin did NOT run → **info** (unverified, just informational)
    """
    ports = _get_hosts_ports(results)
    if not ports:
        return []

    # Check if HTTPS (port 443) or alternative TLS ports are open
    tls_ports = {443, 8443}
    has_tls = any(p.get("port") in tls_ports for p in ports)

    if has_tls:
        return []

    # If the ssl plugin was run, it would have data about TLS availability.
    # Its absence means we simply didn't check — downgrade to info.
    ssl_ran = "ssl" in results and bool(results["ssl"])
    severity = "medium" if ssl_ran else "info"

    return [
        Finding(
            severity=severity,
            title="No HTTPS/TLS service detected",
            description=(
                "Open ports were found on the target but none of them appear "
                "to be an HTTPS/TLS service (ports 443, 8443).  Data in "
                "transit may not be encrypted."
            ) if ssl_ran else (
                "Open ports were found on the target but none of them appear "
                "to be an HTTPS/TLS service (ports 443, 8443).  The SSL/TLS "
                "plugin was not run, so this could not be confirmed."
            ),
            recommendation=(
                "Enable HTTPS by deploying a TLS certificate on port 443 "
                "and redirect all HTTP traffic to HTTPS."
            ),
            source_plugins=["nmap"],
        )
    ]


def check_certificate_expired(results: dict) -> list[Finding]:
    """SSL certificate is expired."""
    ssl_data = results.get("ssl", {})
    cert = ssl_data.get("certificate", {})
    if not isinstance(cert, dict) or not cert.get("is_expired"):
        return []

    return [
        Finding(
            severity="critical",
            title="SSL/TLS certificate has expired",
            description=(
                "The server presents an expired TLS certificate.  Browsers "
                "and clients will display security warnings and may refuse "
                "to connect."
            ),
            recommendation=(
                "Renew the certificate immediately with your Certificate "
                "Authority (CA) and deploy the renewed certificate on the server."
            ),
            source_plugins=["ssl"],
        )
    ]


def check_certificate_self_signed(results: dict) -> list[Finding]:
    """SSL certificate is self-signed."""
    ssl_data = results.get("ssl", {})
    cert = ssl_data.get("certificate", {})
    if not isinstance(cert, dict) or not cert.get("is_self_signed"):
        return []

    return [
        Finding(
            severity="high",
            title="SSL/TLS certificate is self-signed",
            description=(
                "The server uses a self-signed certificate that is not "
                "trusted by any public Certificate Authority.  Clients "
                "will show untrusted certificate warnings."
            ),
            recommendation=(
                "Replace the self-signed certificate with one issued by a "
                "trusted public CA such as Let's Encrypt, DigiCert, or "
                "GlobalSign."
            ),
            source_plugins=["ssl"],
        )
    ]


def check_weak_tls(results: dict) -> list[Finding]:
    """Weak TLS protocols detected (TLS 1.0/1.1)."""
    ssl_data = results.get("ssl", {})
    protocol = ssl_data.get("protocol", {})
    weak_protocols = protocol.get("weak_protocols", [])
    if not weak_protocols:
        return []

    return [
        Finding(
            severity="high",
            title="Weak TLS protocols enabled",
            description=(
                "The server supports deprecated TLS versions: "
                f"{', '.join(sorted(weak_protocols))}.  These protocols "
                "have known vulnerabilities (e.g. POODLE, BEAST) and "
                "should be disabled."
            ),
            recommendation=(
                "Disable TLS 1.0 and TLS 1.1 on the server.  Enable "
                "TLS 1.2 and TLS 1.3 exclusively."
            ),
            source_plugins=["ssl"],
        )
    ]


def check_hsts_missing(results: dict) -> list[Finding]:
    """HTTP Strict-Transport-Security header missing."""
    headers_data = results.get("headers", {})
    hdr_analysis = headers_data.get("headers", {})
    hsts = hdr_analysis.get("Strict-Transport-Security", {})
    if isinstance(hsts, dict) and hsts.get("present", False):
        return []

    # Check if domain is in the HSTS preload list (e.g. google.com, facebook.com)
    target = headers_data.get("target", "")
    if target and _is_hsts_preloaded(target):
        return []

    return [
        Finding(
            severity="medium",
            title="HTTP Strict-Transport-Security header missing",
            description=(
                "The server does not send the Strict-Transport-Security "
                "header.  Without HSTS, browsers may fall back to plain "
                "HTTP and are vulnerable to SSL stripping attacks."
            ),
            recommendation=(
                "Add the HSTS header: "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            source_plugins=["headers"],
        )
    ]


def check_csp_weak(results: dict) -> list[Finding]:
    """Content Security Policy has unsafe directives."""
    headers_data = results.get("headers", {})
    hdr_analysis = headers_data.get("headers", {})
    csp = hdr_analysis.get("Content-Security-Policy", {})
    csp_value = csp.get("value", "") if isinstance(csp, dict) else ""
    if not isinstance(csp_value, str):
        csp_value = ""

    unsafe_directives: list[str] = []
    if "unsafe-inline" in csp_value:
        unsafe_directives.append("'unsafe-inline'")
    if "unsafe-eval" in csp_value:
        unsafe_directives.append("'unsafe-eval'")

    if not unsafe_directives:
        return []

    return [
        Finding(
            severity="medium",
            title="Content Security Policy contains unsafe directives",
            description=(
                "The CSP header includes "
                f"{' and '.join(unsafe_directives)}, which weakens "
                "XSS protections by allowing inline scripts and/or "
                "dynamic code evaluation."
            ),
            recommendation=(
                "Remove 'unsafe-inline' and 'unsafe-eval' from the CSP. "
                "Use nonces or hashes for inline scripts instead."
            ),
            source_plugins=["headers"],
        )
    ]


def check_server_header_leak(results: dict) -> list[Finding]:
    """Server or X-Powered-By headers leak technology info."""
    headers_data = results.get("headers", {})
    leaked = headers_data.get("leaked_headers", {})
    if not leaked:
        return []

    leak_desc = "; ".join(f"{k}: {v}" for k, v in leaked.items())

    return [
        Finding(
            severity="low",
            title="Server technology headers leak internal information",
            description=(
                f"The server exposes the following technology-information "
                f"headers: {leak_desc}.  Attackers can use these details "
                f"to tailor their exploits."
            ),
            recommendation=(
                "Remove or obfuscate the Server, X-Powered-By, and "
                "X-AspNet-Version response headers."
            ),
            source_plugins=["headers"],
        )
    ]


def check_dangerous_ports(results: dict) -> list[Finding]:
    """Dangerous ports open (FTP, Telnet, SMB, RDP)."""
    ports = _get_hosts_ports(results)
    dangerous: list[int] = sorted(
        p.get("port") for p in ports if p.get("port") in DANGEROUS_PORTS
    )
    if not dangerous:
        return []

    port_names = {21: "FTP", 23: "Telnet", 135: "MSRPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP"}
    detail = "; ".join(
        f"port {p} ({port_names.get(p, 'unknown')})" for p in dangerous
    )

    return [
        Finding(
            severity="high",
            title="Dangerous network services exposed",
            description=(
                f"The following high-risk ports are open: {detail}.  "
                f"These services are frequently targeted by attackers "
                f"and are often unpatched or misconfigured."
            ),
            recommendation=(
                "Close unnecessary ports and restrict access to "
                "essential services with a firewall.  If a service "
                "must be exposed, ensure it is patched and configured "
                "securely."
            ),
            source_plugins=["nmap"],
        )
    ]


def check_vt_malicious(results: dict) -> list[Finding]:
    """VirusTotal reports malicious detections."""
    vt_data = results.get("vt", {})
    malicious = vt_data.get("malicious", 0)
    if not isinstance(malicious, (int, float)) or malicious <= 0:
        return []

    return [
        Finding(
            severity="critical",
            title="VirusTotal reports malicious activity",
            description=(
                f"VirusTotal has {int(malicious)} malicious detection(s) "
                f"for this target.  This indicates the domain or IP has "
                f"been associated with malware, phishing, or other threats."
            ),
            recommendation=(
                "Investigate the target immediately.  Scan the affected "
                "systems for malware, review logs for unauthorised access, "
                "and consider taking the service offline until cleaned."
            ),
            source_plugins=["vt"],
        )
    ]


def check_vt_suspicious(results: dict) -> list[Finding]:
    """VirusTotal reports suspicious detections."""
    vt_data = results.get("vt", {})
    suspicious = vt_data.get("suspicious", 0)
    if not isinstance(suspicious, (int, float)) or suspicious <= 0:
        return []

    return [
        Finding(
            severity="medium",
            title="VirusTotal reports suspicious detections",
            description=(
                f"VirusTotal has {int(suspicious)} suspicious detection(s) "
                f"for this target.  While not confirmed malicious, this "
                f"warrants further investigation."
            ),
            recommendation=(
                "Review the VirusTotal report details to understand the "
                "nature of the suspicious detections and take corrective "
                "action if necessary."
            ),
            source_plugins=["vt"],
        )
    ]


def check_dns_subdomains(results: dict) -> list[Finding]:
    """Subdomains discovered — expanded attack surface."""
    dns_data = results.get("dns", {})
    total_subs = dns_data.get("total_subdomains", 0)
    if not isinstance(total_subs, (int, float)) or total_subs <= 0:
        return []

    sub_list = dns_data.get("subdomains", [])
    sub_names = []
    if isinstance(sub_list, list):
        sub_names = [
            s.get("subdomain", "") for s in sub_list if isinstance(s, dict)
        ]

    detail = ", ".join(sub_names[:10])
    if len(sub_names) > 10:
        detail += f" and {len(sub_names) - 10} more"

    return [
        Finding(
            severity="info",
            title=f"Subdomains discovered ({int(total_subs)} found)",
            description=(
                f"DNS enumeration discovered {int(total_subs)} subdomain(s): "
                f"{detail}.  Each subdomain represents an additional entry "
                f"point that may expose vulnerable services."
            ),
            recommendation=(
                "Review all discovered subdomains, ensure they are "
                "properly secured, and remove unused or outdated ones."
            ),
            source_plugins=["dns"],
        )
    ]


def check_banner_information_disclosure(results: dict) -> list[Finding]:
    """Banners reveal version information."""
    banner_data = results.get("banner", {})
    banners = banner_data.get("banners", [])
    if not isinstance(banners, list) or not banners:
        return []

    # Look for version strings in banners (e.g. "OpenSSH_8.9", "nginx/1.18")
    version_patterns = ["_", "/", "version", "Server:"]
    disclosed: list[str] = []
    for b in banners:
        banner_text = b.get("banner", "")
        if isinstance(banner_text, str) and any(
            pat in banner_text.lower() for pat in version_patterns
        ):
            port = b.get("port", "?")
            disclosed.append(f"port {port}: {banner_text[:80]}")

    if not disclosed:
        return []

    return [
        Finding(
            severity="low",
            title="Service banners disclose version information",
            description=(
                f"The following banners expose software version details "
                f"that aid attackers: {'; '.join(disclosed[:5])}"
            ),
            recommendation=(
                "Disable or obfuscate service banners.  For HTTP, remove "
                "the Server header or set a generic value.  For SSH and "
                "other daemons, configure banner suppression in the "
                "respective configuration files."
            ),
            source_plugins=["banner"],
        )
    ]


def check_whois_expiring(results: dict) -> list[Finding]:
    """Domain registration expiring soon."""
    whois_data = results.get("whois", {})
    exp_date_str = whois_data.get("expiration_date", "")
    if not isinstance(exp_date_str, str) or not exp_date_str.strip():
        return []

    # Try multiple date formats commonly returned by WHOIS servers
    date_formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%Y/%m/%d",
        "%d %b %Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    exp_date: datetime.datetime | None = None
    for fmt in date_formats:
        try:
            exp_date = datetime.datetime.strptime(
                exp_date_str.strip(), fmt
            )
            break
        except (ValueError, TypeError):
            continue

    if exp_date is None:
        return []

    now = datetime.datetime.now()
    # Make naive datetimes comparable
    if exp_date.tzinfo is not None:
        exp_date = exp_date.replace(tzinfo=None)

    days_until_expiry = (exp_date - now).days
    if days_until_expiry < 0:
        return [
            Finding(
                severity="high",
                title="Domain registration has expired",
                description=(
                    f"The domain registration expired on "
                    f"{exp_date_str.strip()}.  An expired domain can be "
                    f"registered by third parties, leading to service "
                    f"disruption or impersonation."
                ),
                recommendation=(
                    "Renew the domain registration immediately."
                ),
                source_plugins=["whois"],
            )
        ]

    if days_until_expiry <= 90:
        return [
            Finding(
                severity="medium",
                title="Domain registration expiring soon",
                description=(
                    f"The domain will expire in {days_until_expiry} day(s) "
                    f"on {exp_date_str.strip()}.  Failure to renew may "
                    f"result in service downtime."
                ),
                recommendation=(
                    "Renew the domain registration before the expiration "
                    "date to avoid service interruption."
                ),
                source_plugins=["whois"],
            )
        ]

    return []


def check_weak_ciphers(results: dict) -> list[Finding]:
    """Weak cipher suites detected."""
    ssl_data = results.get("ssl", {})
    cipher = ssl_data.get("cipher", {})

    cipher_is_weak = cipher.get("is_weak", False) if isinstance(cipher, dict) else False
    cipher_name = cipher.get("name", "") if isinstance(cipher, dict) else ""

    if not cipher_is_weak and not cipher_name:
        return []

    if not cipher_is_weak:
        return []

    return [
        Finding(
            severity="high",
            title="Weak cipher suite negotiated",
            description=(
                f"The server negotiated a weak cipher: {cipher_name}.  "
                f"Weak ciphers (RC4, DES, 3DES, etc.) are vulnerable to "
                f"cryptanalytic attacks."
            ),
            recommendation=(
                "Disable weak ciphers on the server.  Configure the server "
                "to only accept strong ciphers such as AES-GCM or "
                "ChaCha20-Poly1305."
            ),
            source_plugins=["ssl"],
        )
    ]


def check_missing_headers(results: dict) -> list[Finding]:
    """Security headers missing — split by severity."""
    headers_data = results.get("headers", {})
    hdr_analysis = headers_data.get("headers", {})

    # X-Frame-Options: medium (clickjacking risk)
    xfo = hdr_analysis.get("X-Frame-Options", {})
    if isinstance(xfo, dict) and not xfo.get("present", False):
        return [
            Finding(
                severity="medium",
                title="X-Frame-Options header missing",
                description=(
                    "The server does not send the X-Frame-Options header. "
                    "Without it, the site may be embedded in iframes on "
                    "other domains, enabling clickjacking attacks."
                ),
                recommendation="Add X-Frame-Options: DENY or SAMEORIGIN.",
                source_plugins=["headers"],
            )
        ]

    # X-Content-Type-Options: low (best practice, not critical)
    xcto = hdr_analysis.get("X-Content-Type-Options", {})
    if isinstance(xcto, dict) and not xcto.get("present", False):
        return [
            Finding(
                severity="low",
                title="X-Content-Type-Options header missing",
                description=(
                    "The server does not send the X-Content-Type-Options "
                    "header. Without nosniff, browsers may MIME-sniff "
                    "responses and interpret them as a different content type."
                ),
                recommendation="Add X-Content-Type-Options: nosniff.",
                source_plugins=["headers"],
            )
        ]

    return []


def check_no_plugins_ran(results: dict) -> list[Finding]:
    """Warn when no plugin results were provided for analysis."""
    if not results:
        return [
            Finding(
                severity="info",
                title="No scan results to analyse",
                description=(
                    "The results dictionary is empty.  No plugins were "
                    "executed or all returned empty data."
                ),
                recommendation=(
                    "Run at least one scan plugin (e.g. nmap, ssl, headers) "
                    "before requesting analysis."
                ),
                source_plugins=[],
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Master rule list — ordered by severity / category
# ---------------------------------------------------------------------------

ALL_RULES: list[Callable[[dict], list[Finding]]] = [
    check_no_plugins_ran,
    check_certificate_expired,
    check_vt_malicious,
    check_certificate_self_signed,
    check_weak_tls,
    check_dangerous_ports,
    check_weak_ciphers,
    check_open_ports_no_https,
    check_hsts_missing,
    check_csp_weak,
    check_missing_headers,
    check_whois_expiring,
    check_vt_suspicious,
    check_server_header_leak,
    check_banner_information_disclosure,
    check_dns_subdomains,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_rules(results: dict) -> list[Finding]:
    """Run all rules against *results* and return accumulated findings.

    Parameters
    ----------
    results : dict
        Dictionary keyed by plugin name containing each plugin's output dict.

    Returns
    -------
    list[Finding]
        Combined findings from all rules.
    """
    findings: list[Finding] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(results))
        except Exception:
            logger.exception("Rule %s crashed — skipping", rule.__name__)
    return findings
