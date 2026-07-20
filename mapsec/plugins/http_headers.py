"""HTTP Security Headers analysis plugin — pure Python, no external tools required."""

from __future__ import annotations

import asyncio
import re
import ssl
import urllib.request
from typing import Any
from urllib.error import HTTPError, URLError

from mapsec.core.plugin import BasePlugin, register_plugin


# ── Security Headers Reference ──────────────────────────────────────────────

SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "weight": "high",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS, injection attacks",
        "weight": "high",
        "recommendation": "Define specific source whitelist",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "weight": "medium",
        "recommendation": "nosniff",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "weight": "medium",
        "recommendation": "DENY or SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful)",
        "weight": "low",
        "recommendation": "1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "weight": "medium",
        "recommendation": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "weight": "medium",
        "recommendation": "Restrict camera, microphone, geolocation, etc.",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "weight": "low",
        "recommendation": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents hotlinking",
        "weight": "low",
        "recommendation": "same-origin",
    },
}

LEAKED_HEADERS: set[str] = {
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
}

WEIGHT_VALUES: dict[str, int] = {
    "high": 15,
    "medium": 10,
    "low": 5,
}


# ── Plugin ──────────────────────────────────────────────────────────────────


@register_plugin
class HttpHeadersPlugin(BasePlugin):
    """HTTP security headers analysis plugin.

    Sends an HTTP GET request to the target, inspects all response headers
    for security-related fields, scores each header (present / missing /
    weak), detects information-leaking headers, and produces an overall
    security rating (A–F).
    """

    name = "headers"
    description = "HTTP security headers analysis"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, target: str) -> dict[str, Any]:
        """Execute HTTP security headers analysis against *target*.

        Args:
            target: Domain name or IP address to analyse.

        Returns:
            Dictionary with keys ``target``, ``url``, ``status_code``,
            ``headers``, ``leaked_headers``, ``score``, ``warnings``.
        """
        url, status_code, response_headers = await self._fetch_headers(target)

        headers_analysis = self._analyze_headers(response_headers)
        leaked = self._find_leaked_headers(response_headers)
        warnings = self._generate_warnings(
            headers_analysis, leaked, response_headers
        )
        score = self._calculate_score(
            headers_analysis, leaked, response_headers
        )

        return {
            "target": target,
            "url": url,
            "status_code": status_code,
            "headers": headers_analysis,
            "leaked_headers": leaked,
            "score": score,
            "warnings": warnings,
        }

    def validate_target(self, target: str) -> bool:
        """Validate *target* is a valid IP address or hostname."""
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        hostname_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
        )
        return bool(
            re.match(ipv4_pattern, target)
            or re.match(hostname_pattern, target)
        )

    # ------------------------------------------------------------------
    # HTTP request helpers
    # ------------------------------------------------------------------

    async def _fetch_headers(
        self, target: str
    ) -> tuple[str, int, dict[str, str]]:
        """Fetch response headers from *target*.

        Tries HTTPS first and falls back to plain HTTP on any connection /
        SSL / timeout error.
        """
        schemes = ["https", "http"]

        for scheme in schemes:
            url = f"{scheme}://{target}"
            try:
                status_code, headers = await asyncio.to_thread(
                    self._make_request, url
                )
                return url, status_code, headers
            except (URLError, ssl.SSLError, OSError, ValueError):
                if scheme == schemes[-1]:
                    raise  # Re-raise if the last scheme also failed

        # Unreachable — both schemes exhausted without success
        return "", 0, {}

    def _make_request(self, url: str) -> tuple[int, dict[str, str]]:
        """Synchronous HTTP GET that returns ``(status_code, headers_dict)``.

        * Follows up to 5 redirects.
        * Uses an SSL context that does **not** verify certificates (needed
          for self-signed or internal certificates).
        * On HTTP errors (4xx, 5xx, or too many redirects), the response
          headers are still extracted from the exception object.
        """
        # SSL context — accept any certificate for scanning purposes
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # -- Redirect handler — cap automatic following at 5 hops ----------
        class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self, req, fp, code, msg, headers, newurl
            ):  # noqa: N802, PLR6301
                redirect_count = getattr(req, "_redirect_count", 0) + 1
                if redirect_count > 5:
                    return None  # Stop following
                new_req = super().redirect_request(
                    req, fp, code, msg, headers, newurl
                )
                if new_req is not None:
                    new_req._redirect_count = redirect_count
                return new_req

        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler, LimitedRedirectHandler)

        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "Mapsec/0.1.0"},
        )

        try:
            with opener.open(req, timeout=10) as resp:
                return resp.getcode() or 0, dict(resp.headers.items())
        except HTTPError as exc:
            # Extract headers from error responses (4xx, 5xx, or unhandled
            # redirect beyond our 5-hop limit) so we can still score them.
            err_headers: dict[str, str] = {}
            raw = getattr(exc, "hdrs", None) or getattr(exc, "headers", None)
            if raw is not None:
                err_headers = dict(raw.items())
            return exc.code, err_headers

    # ------------------------------------------------------------------
    # Header analysis helpers
    # ------------------------------------------------------------------

    def _analyze_headers(
        self, headers: dict[str, str]
    ) -> dict[str, dict[str, bool | str]]:
        """Check presence of each known security header.

        Returns a dict keyed by canonical header name with ``present``,
        ``value`` and ``status`` fields.
        """
        lower_map = {k.lower(): v for k, v in headers.items()}
        result: dict[str, dict[str, bool | str]] = {}

        for hdr, info in SECURITY_HEADERS.items():
            value = lower_map.get(hdr.lower(), "")
            present = bool(value)
            result[hdr] = {
                "present": present,
                "value": value if present else "",
                "status": "good" if present else "missing",
            }

        return result

    def _find_leaked_headers(
        self, headers: dict[str, str]
    ) -> dict[str, str]:
        """Return headers that leak server / technology version information.

        Performs case-insensitive key matching and returns the canonical
        leaked-header names as keys.
        """
        lower_map = {k.lower(): k for k in headers}
        leaked: dict[str, str] = {}

        for hdr in LEAKED_HEADERS:
            original_key = lower_map.get(hdr.lower())
            if original_key is not None:
                leaked[hdr] = headers[original_key]

        return leaked

    @staticmethod
    def _get_header_value(
        headers: dict[str, str], name: str
    ) -> str | None:
        """Case-insensitive header value lookup."""
        lower = name.lower()
        for k, v in headers.items():
            if k.lower() == lower:
                return v
        return None

    def _generate_warnings(
        self,
        headers_analysis: dict[str, dict[str, bool | str]],
        leaked_headers: dict[str, str],
        raw_headers: dict[str, str],
    ) -> list[str]:
        """Build a human-readable warning list."""
        warnings: list[str] = []

        # -- Missing security headers --
        for hdr, info in headers_analysis.items():
            if not info["present"]:
                warnings.append(f"Missing {hdr} header")

        # -- Weak HSTS --
        hsts = self._get_header_value(
            raw_headers, "Strict-Transport-Security"
        )
        if hsts:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts)
            if m:
                max_age = int(m.group(1))
                if max_age < 31536000:
                    warnings.append(
                        f"Weak HSTS: max-age={max_age} "
                        f"(recommended >= 31536000)"
                    )

        # -- Weak CSP --
        csp = self._get_header_value(
            raw_headers, "Content-Security-Policy"
        )
        if csp:
            if "unsafe-inline" in csp:
                warnings.append("Weak CSP: contains 'unsafe-inline'")
            if "unsafe-eval" in csp:
                warnings.append("Weak CSP: contains 'unsafe-eval'")

        # -- Leaked server / technology headers --
        for hdr, val in leaked_headers.items():
            warnings.append(f"{hdr} header leaks version: {val}")

        return warnings

    def _calculate_score(
        self,
        headers_analysis: dict[str, dict[str, bool | str]],
        leaked_headers: dict[str, str],
        raw_headers: dict[str, str],
    ) -> dict[str, int | str]:
        """Compute numeric score (0–100), letter grade (A–F), and counts.

        Scoring rules:
        * High-weight header present  → +15
        * Medium-weight header present → +10
        * Low-weight header present   →  +5
        * Any missing header          →  -5
        * Each leaked header          →  -5
        * Weak HSTS (max-age < 31536000) → -10
        * Weak CSP (unsafe-inline or unsafe-eval) → -10

        Letter grades:
            A (≥90), B (70–89), C (50–69), D (30–49), F (<30)
        """
        score = 0
        present_count = 0
        missing_count = 0

        for hdr, info in headers_analysis.items():
            weight = SECURITY_HEADERS[hdr]["weight"]
            if info["present"]:
                score += WEIGHT_VALUES[weight]
                present_count += 1
            else:
                score -= 5
                missing_count += 1

        # Penalty — leaked technology info
        score -= len(leaked_headers) * 5

        # Penalty — weak HSTS
        hsts = self._get_header_value(
            raw_headers, "Strict-Transport-Security"
        )
        if hsts:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts)
            if m and int(m.group(1)) < 31536000:
                score -= 10

        # Penalty — weak CSP
        csp = self._get_header_value(
            raw_headers, "Content-Security-Policy"
        )
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
            score -= 10

        # Clamp to valid range
        score = max(0, min(100, score))

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        return {
            "grade": grade,
            "score": score,
            "missing_count": missing_count,
            "present_count": present_count,
        }
