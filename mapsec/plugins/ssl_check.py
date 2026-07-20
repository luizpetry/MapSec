"""SSL/TLS certificate and protocol analysis plugin."""

from __future__ import annotations

import asyncio
import datetime
import re
import socket
import ssl
from typing import Any

from mapsec.core.plugin import BasePlugin, register_plugin

# ── Security constants ──────────────────────────────────────────────────────

WEAK_PROTOCOLS: set[str] = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS: set[str] = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}

# ── Protocol test matrix ────────────────────────────────────────────────────
# Build the list of (TLSVersion enum, human label) tuples filtering out any
# enum members not available on the current platform / OpenSSL build.
_PROTOCOL_TESTS: list[tuple[ssl.TLSVersion, str]] = []
for _attr, _label in [
    ("SSLv3", "SSLv3"),
    ("TLSv1", "TLSv1"),
    ("TLSv1_1", "TLSv1.1"),
    ("TLSv1_2", "TLSv1.2"),
    ("TLSv1_3", "TLSv1.3"),
]:
    _ver = getattr(ssl.TLSVersion, _attr, None)
    if _ver is not None:
        _PROTOCOL_TESTS.append((_ver, _label))

# ── Date parsing ────────────────────────────────────────────────────────────
# TLS certificate dates from getpeercert() look like:
#   "Jan  1 00:00:00 2024 GMT"   (single-digit day → double space)
#   "Jan 10 00:00:00 2024 GMT"   (double-digit day → single space)

_DATE_FORMATS: list[str] = [
    "%b %d %H:%M:%S %Y %Z",
    "%b  %d %H:%M:%S %Y %Z",
]


def _parse_tls_date(date_str: str) -> datetime.datetime | None:
    """Parse a TLS certificate date string into a timezone-naive datetime.

    The string is returned by ``ssl.SSLObject.getpeercert()`` and is always
    expressed in GMT (UTC).
    """
    for fmt in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    # Last-resort: normalise all whitespace and try again
    normalized = re.sub(r"\s+", " ", date_str).strip()
    try:
        return datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def _get_cn(rdn_tuple: tuple) -> str:
    """Extract the Common Name (CN) from an X.509 RDN tuple.

    The RDN structure returned by ``getpeercert()`` is a tuple of tuples of
    ``((key, value),)`` pairs.  For example::

        (
            (("countryName", "US"),),
            (("organizationName", "Example Inc."),),
            (("commonName", "example.com"),),
        )
    """
    for attr_tuple in rdn_tuple:
        if attr_tuple and len(attr_tuple) > 0:
            key, value = attr_tuple[0]
            if key == "commonName":
                return value
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin
# ═══════════════════════════════════════════════════════════════════════════════


@register_plugin
class SslCheckPlugin(BasePlugin):
    """SSL/TLS certificate and protocol analysis plugin.

    Connects to a target on a configurable port (default 443), retrieves the
    X.509 certificate, inspects the negotiated protocol version and cipher
    suite, and reports security weaknesses.

    Pure-Python implementation — no external dependencies beyond the standard
    library (``ssl``, ``socket``, ``asyncio``, ``datetime``).
    """

    name = "ssl"
    description = "SSL/TLS certificate and protocol analysis"

    def __init__(self, port: int = 443) -> None:
        self.port = port

    # ── Public API ──────────────────────────────────────────────────────────

    async def run(self, target: str) -> dict[str, Any]:
        """Execute SSL/TLS analysis against *target*.

        Parameters
        ----------
        target : str
            Hostname or IP address to analyse.

        Returns
        -------
        dict
            Structured results containing certificate, protocol, cipher, and
            warnings keys (see plugin specification for the full schema).
        """
        # Resolve hostname → IP (best-effort, non-fatal)
        ip = await self._resolve(target)

        # ── 1. Establish SSL connection ────────────────────────────────
        try:
            conn_info = await asyncio.wait_for(
                asyncio.to_thread(self._connect_ssl, target, self.port),
                timeout=10,
            )
        except (
            ConnectionRefusedError,
            ConnectionResetError,
            socket.timeout,
            OSError,
            ssl.SSLError,
            ssl.CertificateError,
        ) as exc:
            return {
                "target": target,
                "port": self.port,
                "certificate": {},
                "protocol": {},
                "cipher": {},
                "warnings": [f"Connection failed: {exc}"],
            }

        cert_dict = conn_info.pop("cert_dict", None)

        # ── 2. Certificate analysis ────────────────────────────────────
        cert_info = self._extract_cert_info(cert_dict)

        # ── 3. Protocol analysis ───────────────────────────────────────
        version = conn_info.get("version", "unknown")
        is_version_secure = version not in WEAK_PROTOCOLS

        weak_protocols = await self._detect_weak_protocols(target, self.port)

        # ── 4. Cipher analysis ─────────────────────────────────────────
        cipher_name = conn_info.get("cipher_name", "")
        cipher_bits = conn_info.get("cipher_bits", 0)
        is_cipher_weak = any(
            wc.lower() in cipher_name.lower() for wc in WEAK_CIPHERS
        )

        # ── 5. Warnings ────────────────────────────────────────────────
        warnings: list[str] = []

        if weak_protocols:
            warnings.append(
                f"Server supports weak protocols: {', '.join(sorted(weak_protocols))}"
            )

        if is_cipher_weak:
            warnings.append(f"Weak cipher negotiated: {cipher_name}")

        if cert_info.get("is_expired"):
            warnings.append("Certificate has expired")

        if cert_info.get("is_self_signed"):
            warnings.append("Certificate is self-signed")

        expiry_days = cert_info.get("days_until_expiry")
        if isinstance(expiry_days, (int, float)) and 0 < expiry_days < 30:
            warnings.append(
                f"Certificate expires in {int(expiry_days)} days"
            )

        return {
            "target": target,
            "port": self.port,
            "certificate": cert_info,
            "protocol": {
                "version": version,
                "is_secure": is_version_secure,
                "weak_protocols": weak_protocols,
            },
            "cipher": {
                "name": cipher_name,
                "bits": cipher_bits,
                "is_weak": is_cipher_weak,
            },
            "warnings": warnings,
        }

    def validate_target(self, target: str) -> bool:
        """Return ``True`` if *target* looks like an IP or hostname.

        Uses the same validation logic as :class:`NmapPlugin`.
        """
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        hostname_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
        )
        return bool(
            re.match(ipv4_pattern, target)
            or re.match(hostname_pattern, target)
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _resolve(self, target: str) -> str:
        """Resolve *target* to an IPv4 address (best-effort).

        Returns the original *target* string if resolution fails.
        """
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo, target, self.port, socket.AF_INET
            )
            return infos[0][4][0] if infos else target
        except socket.gaierror:
            return target

    def _connect_ssl(self, host: str, port: int) -> dict[str, Any]:
        """Open a TLS connection and return certificate + negotiated metadata.

        This method is blocking and intended to be called via
        ``asyncio.to_thread()``.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert(binary_form=False)
                version = ssock.version()
                cipher = ssock.cipher()

        return {
            "cert_dict": cert_dict,
            "version": version or "unknown",
            "cipher_name": cipher[0] if cipher else "",
            "cipher_bits": cipher[1] if cipher else 0,
        }

    # ── Certificate extraction ──────────────────────────────────────────

    def _extract_cert_info(self, cert_dict: dict | None) -> dict[str, Any]:
        """Extract structured information from a raw ``getpeercert()`` dict.

        Returns a dictionary with the keys defined in the plugin output
        specification, using sensible defaults when data is missing.
        """
        if not cert_dict:
            return {
                "issuer": "",
                "subject": "",
                "valid_from": "",
                "valid_until": "",
                "days_until_expiry": 0,
                "serial": "",
                "san": [],
                "is_expired": False,
                "is_self_signed": False,
            }

        subject = _get_cn(cert_dict.get("subject", ()))
        issuer = _get_cn(cert_dict.get("issuer", ()))

        # ── Dates ──────────────────────────────────────────────────────
        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")

        valid_from_dt = (
            _parse_tls_date(not_before_str) if not_before_str else None
        )
        valid_until_dt = (
            _parse_tls_date(not_after_str) if not_after_str else None
        )

        # The dates returned by getpeercert() are always GMT but
        # strptime does *not* attach a tzinfo; we assume UTC here so that
        # arithmetic with aware datetimes works correctly.
        _utc = datetime.timezone.utc
        now = datetime.datetime.now(_utc)

        if valid_from_dt is not None and valid_from_dt.tzinfo is None:
            valid_from_dt = valid_from_dt.replace(tzinfo=_utc)
        if valid_until_dt is not None and valid_until_dt.tzinfo is None:
            valid_until_dt = valid_until_dt.replace(tzinfo=_utc)

        days_until_expiry = (
            (valid_until_dt - now).days if valid_until_dt else 0
        )

        # ── SAN (Subject Alternative Names) ────────────────────────────
        san_raw = cert_dict.get("subjectAltName", ())
        san = [entry[1] for entry in san_raw if entry[0] == "DNS"]

        # ── Serial number ──────────────────────────────────────────────
        serial = cert_dict.get("serialNumber", "")

        # ── Flags ──────────────────────────────────────────────────────
        is_self_signed = bool(subject and issuer and subject == issuer)
        is_expired = valid_until_dt is not None and valid_until_dt < now

        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": (
                valid_from_dt.strftime("%Y-%m-%dT%H:%M:%S")
                if valid_from_dt
                else ""
            ),
            "valid_until": (
                valid_until_dt.strftime("%Y-%m-%dT%H:%M:%S")
                if valid_until_dt
                else ""
            ),
            "days_until_expiry": days_until_expiry,
            "serial": serial,
            "san": san,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
        }

    # ── Weak protocol detection ────────────────────────────────────────

    async def _detect_weak_protocols(
        self, host: str, port: int
    ) -> list[str]:
        """Probe the server for each weak protocol version.

        Returns the list of protocol labels (e.g. ``"TLSv1"``) that the
        server accepts.  Only protocols in :data:`WEAK_PROTOCOLS` are
        probed; modern versions are skipped to reduce latency.
        """
        weak_found: list[str] = []

        async def _probe(
            tls_version: ssl.TLSVersion, label: str
        ) -> str | None:
            if label not in WEAK_PROTOCOLS:
                return None

            def _try_connect() -> bool:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    try:
                        ctx.minimum_version = tls_version
                        ctx.maximum_version = tls_version
                    except (ValueError, NotImplementedError):
                        # Platform/OpenSSL does not support this version
                        return False
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection(
                        (host, port), timeout=5
                    ) as sock:
                        with ctx.wrap_socket(
                            sock, server_hostname=host
                        ):
                            pass
                    return True
                except (ssl.SSLError, OSError, socket.timeout):
                    return False

            result = await asyncio.to_thread(_try_connect)
            return label if result else None

        tasks = [_probe(ver, name) for ver, name in _PROTOCOL_TESTS]
        results = await asyncio.gather(*tasks)
        return sorted(r for r in results if r is not None)
