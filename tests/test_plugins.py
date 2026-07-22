"""Tests for built-in plugins: NmapPlugin, DnsPlugin, WhoisPlugin, BannerGrabPlugin, SslCheckPlugin, HttpHeadersPlugin, ShodanPlugin, CveLookupPlugin."""

import json
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from mapsec.plugins.nmap_scan import NmapPlugin
from mapsec.plugins.dns_enum import DnsPlugin
from mapsec.plugins.whois_lookup import WhoisPlugin
from mapsec.plugins.banner_grab import BannerGrabPlugin
from mapsec.plugins.ssl_check import SslCheckPlugin
from mapsec.plugins.http_headers import HttpHeadersPlugin
from mapsec.plugins.shodan_lookup import ShodanPlugin
from mapsec.plugins.cve_lookup import CveLookupPlugin
from mapsec.services.exploit_advisor import ExploitAdvisor


# ── NmapPlugin ────────────────────────────────────────────────────────────


class TestNmapPluginValidateTarget:
    """Tests for NmapPlugin.validate_target()."""

    def test_accepts_valid_ipv4(self):
        """validate_target returns True for valid IPv4 addresses."""
        plugin = NmapPlugin()
        for ip in ["192.168.1.1", "10.0.0.1", "8.8.8.8", "0.0.0.0", "255.255.255.255"]:
            assert plugin.validate_target(ip) is True, f"Should accept {ip}"

    def test_accepts_valid_hostnames(self):
        """validate_target returns True for valid hostnames."""
        plugin = NmapPlugin()
        for hostname in ["localhost", "example.com", "my-host.com", "test.local", "a.b"]:
            assert plugin.validate_target(hostname) is True, f"Should accept {hostname}"

    def test_rejects_empty_string(self):
        """validate_target returns False for empty string."""
        plugin = NmapPlugin()
        assert plugin.validate_target("") is False

    def test_rejects_whitespace_only(self):
        """validate_target returns False for whitespace-only strings."""
        plugin = NmapPlugin()
        assert plugin.validate_target("   ") is False

    def test_rejects_special_characters(self):
        """validate_target returns False for strings with special characters."""
        plugin = NmapPlugin()
        assert plugin.validate_target("!@#$%") is False
        assert plugin.validate_target("example.com!") is False

    def test_rejects_invalid_ip_format(self):
        """validate_target returns False for strings that don't match IP or hostname patterns."""
        plugin = NmapPlugin()
        # IP with trailing dot (no final digit group)
        assert plugin.validate_target("1.2.3.") is False
        # All dots — no digits to match
        assert plugin.validate_target("....") is False
        # String starting with dot (invalid hostname start)
        assert plugin.validate_target(".hidden") is False
        # Double dot — invalid hostname pattern
        assert plugin.validate_target("test..com") is False

    def test_accepts_single_word_hostname(self):
        """validate_target returns True for a single-word hostname."""
        plugin = NmapPlugin()
        assert plugin.validate_target("localhost") is True

    def test_accepts_hostname_with_numbers(self):
        """validate_target returns True for hostnames containing digits."""
        plugin = NmapPlugin()
        assert plugin.validate_target("server01.example.com") is True


@pytest.mark.asyncio
class TestNmapPluginRun:
    """Tests for NmapPlugin.run()."""

    async def test_run_returns_dict_with_hosts_key(self):
        """run() returns a dictionary containing the 'hosts' key."""
        plugin = NmapPlugin()
        with (
            patch("mapsec.plugins.nmap_scan.socket.getaddrinfo") as mock_gai,
            patch("mapsec.plugins.nmap_scan.asyncio.open_connection") as mock_conn,
        ):
            # getaddrinfo returns [(family, type, proto, canonname, sockaddr)]
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            # No ports open → asyncio.open_connection raises
            mock_conn.side_effect = ConnectionRefusedError()

            result = await plugin.run("example.com")

        assert "hosts" in result
        assert isinstance(result["hosts"], list)

    async def test_run_returns_scan_info(self):
        """run() returns a dictionary containing scan_info."""
        plugin = NmapPlugin()
        with (
            patch("mapsec.plugins.nmap_scan.socket.getaddrinfo") as mock_gai,
            patch("mapsec.plugins.nmap_scan.asyncio.open_connection") as mock_conn,
        ):
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            mock_conn.side_effect = ConnectionRefusedError()

            result = await plugin.run("example.com")

        assert "scan_info" in result

    async def test_run_reports_no_open_ports(self):
        """run() returns empty ports list when no ports are open."""
        plugin = NmapPlugin()
        with (
            patch("mapsec.plugins.nmap_scan.socket.getaddrinfo") as mock_gai,
            patch("mapsec.plugins.nmap_scan.asyncio.open_connection") as mock_conn,
        ):
            mock_gai.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            mock_conn.side_effect = ConnectionRefusedError()

            result = await plugin.run("10.0.0.1")

        assert result["hosts"][0]["ports"] == []

    async def test_run_includes_resolved_ip(self):
        """run() includes the resolved IP address in the host entry."""
        plugin = NmapPlugin()
        with (
            patch("mapsec.plugins.nmap_scan.socket.getaddrinfo") as mock_gai,
            patch("mapsec.plugins.nmap_scan.asyncio.open_connection") as mock_conn,
        ):
            mock_gai.return_value = [(2, 1, 6, "", ("192.0.2.1", 0))]
            mock_conn.side_effect = ConnectionRefusedError()

            result = await plugin.run("example.com")

        assert result["hosts"][0]["ip"] == "192.0.2.1"

    async def test_run_detects_open_port(self):
        """run() reports a port as open when the connection succeeds."""
        plugin = NmapPlugin()
        with (
            patch("mapsec.plugins.nmap_scan.socket.getaddrinfo") as mock_gai,
            patch("mapsec.plugins.nmap_scan.asyncio.open_connection") as mock_conn,
        ):
            mock_gai.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            # Simulate port 80 being open
            # Use Mock (not AsyncMock) for writer — close() is sync in real code
            mock_writer = Mock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            # Make only port 80 succeed; everything else fails
            async def _open_connection(host, port):
                if port == 80:
                    return (Mock(), mock_writer)
                raise ConnectionRefusedError()
            mock_conn.side_effect = _open_connection

            result = await plugin.run("10.0.0.1")

        ports = result["hosts"][0]["ports"]
        assert len(ports) == 1
        assert ports[0]["port"] == 80
        assert ports[0]["state"] == "open"
        assert ports[0]["service"]["name"] == "http"


# ── DnsPlugin ─────────────────────────────────────────────────────────────


class TestDnsPluginValidateTarget:
    """Tests for DnsPlugin.validate_target()."""

    def test_accepts_valid_domains(self):
        """validate_target returns True for valid domain names."""
        plugin = DnsPlugin()
        for domain in ["example.com", "sub.example.com", "my-host.com", "test.co.uk", "a.b.c.org"]:
            assert plugin.validate_target(domain) is True, f"Should accept {domain}"

    def test_rejects_empty_string(self):
        """validate_target returns False for empty string."""
        plugin = DnsPlugin()
        assert plugin.validate_target("") is False

    def test_rejects_whitespace_only(self):
        """validate_target returns False for whitespace-only strings."""
        plugin = DnsPlugin()
        assert plugin.validate_target("   ") is False

    def test_rejects_single_word_no_dot(self):
        """validate_target returns False for a single word without a dot."""
        plugin = DnsPlugin()
        assert plugin.validate_target("localhost") is False
        assert plugin.validate_target("notadomain") is False

    def test_rejects_special_characters(self):
        """validate_target returns False for strings with invalid characters."""
        plugin = DnsPlugin()
        assert plugin.validate_target("exam ple.com") is False
        assert plugin.validate_target("example!.com") is False
        assert plugin.validate_target("@example.com") is False

    def test_rejects_strings_without_letter_start(self):
        """validate_target returns False if the domain does not start with an alphanumeric."""
        plugin = DnsPlugin()
        assert plugin.validate_target(".com") is False
        assert plugin.validate_target("-example.com") is False

    def test_rejects_trailing_dot(self):
        """validate_target returns False for domains with a trailing dot."""
        plugin = DnsPlugin()
        assert plugin.validate_target("example.com.") is False


@pytest.mark.asyncio
class TestDnsPluginRun:
    """Tests for DnsPlugin.run()."""

    async def test_run_returns_dict_with_required_keys(self):
        """run() returns a dict containing domain, records, and subdomains."""
        plugin = DnsPlugin()
        with (
            patch("mapsec.plugins.dns_enum.socket.getaddrinfo") as mock_gai,
            patch.object(plugin, "_resolve_mx", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_ns", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_txt", AsyncMock(return_value=[])),
        ):
            # getaddrinfo for A record
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

            result = await plugin.run("example.com")

        assert "domain" in result
        assert "records" in result
        assert "subdomains" in result
        assert result["domain"] == "example.com"

    async def test_run_returns_records_with_a_address(self):
        """run() resolves A records for the domain."""
        plugin = DnsPlugin()
        with (
            patch("mapsec.plugins.dns_enum.socket.getaddrinfo") as mock_gai,
            patch.object(plugin, "_resolve_mx", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_ns", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_txt", AsyncMock(return_value=[])),
        ):
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

            result = await plugin.run("example.com")

        assert "A" in result["records"]
        assert "93.184.216.34" in result["records"]["A"]

    async def test_run_handles_resolution_failure(self):
        """run() gracefully handles DNS resolution failure."""
        plugin = DnsPlugin()
        with (
            patch("mapsec.plugins.dns_enum.socket.getaddrinfo") as mock_gai,
            patch.object(plugin, "_resolve_mx", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_ns", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_txt", AsyncMock(return_value=[])),
        ):
            # Simulate lookup failure
            import socket as _socket
            mock_gai.side_effect = _socket.gaierror("Name or service not known")

            result = await plugin.run("nonexistent.example.com")

        assert result["records"]["A"] == []
        assert result["records"]["AAAA"] == []

    async def test_run_subdomain_enumeration_returns_list(self):
        """run() returns subdomains as a list (possibly empty)."""
        plugin = DnsPlugin()
        with (
            patch("mapsec.plugins.dns_enum.socket.getaddrinfo") as mock_gai,
            patch.object(plugin, "_resolve_mx", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_ns", AsyncMock(return_value=[])),
            patch.object(plugin, "_resolve_txt", AsyncMock(return_value=[])),
        ):
            # getaddrinfo fails for subdomains → empty subdomain list
            import socket as _socket
            mock_gai.side_effect = _socket.gaierror("not found")

            result = await plugin.run("example.com")

        assert isinstance(result["subdomains"], list)
        assert result["total_subdomains"] == 0


# ── WhoisPlugin ─────────────────────────────────────────────────────────


class TestWhoisPluginValidateTarget:
    """Tests for WhoisPlugin.validate_target()."""

    def test_accepts_valid_domains(self):
        plugin = WhoisPlugin()
        for domain in ["example.com", "sub.example.com", "my-host.org", "test.co.uk"]:
            assert plugin.validate_target(domain) is True, f"Should accept {domain}"

    def test_accepts_valid_ipv4(self):
        plugin = WhoisPlugin()
        for ip in ["192.168.1.1", "10.0.0.1", "8.8.8.8"]:
            assert plugin.validate_target(ip) is True, f"Should accept {ip}"

    def test_rejects_empty_string(self):
        assert WhoisPlugin().validate_target("") is False

    def test_rejects_single_word(self):
        assert WhoisPlugin().validate_target("localhost") is False

    def test_rejects_special_characters(self):
        assert WhoisPlugin().validate_target("!@#$%") is False


@pytest.mark.asyncio
class TestWhoisPluginRun:
    """Tests for WhoisPlugin.run()."""

    async def test_run_returns_required_keys(self):
        plugin = WhoisPlugin()
        mock_response = (
            b"Registrar: Example Registrar\n"
            b"Creation Date: 2020-01-01\n"
            b"Registry Expiry Date: 2030-01-01\n"
            b"Name Server: ns1.example.com\n"
            b"Name Server: ns2.example.com\n"
            b"Registrant Organization: Example Org\n"
            b"Registrant Country: US\n"
        )
        with patch.object(plugin, "_whois_query", new_callable=AsyncMock, return_value=mock_response.decode()):
            result = await plugin.run("example.com")

        assert result["target"] == "example.com"
        assert result["type"] == "domain"
        assert "registrar" in result
        assert "creation_date" in result
        assert "name_servers" in result
        assert "registrant" in result

    async def test_run_handles_connection_error(self):
        plugin = WhoisPlugin()
        with patch.object(plugin, "_whois_query", new_callable=AsyncMock, return_value="# ERROR: timeout"):
            result = await plugin.run("example.com")
        assert result["target"] == "example.com"
        assert result["registrar"] == ""

    async def test_run_ip_target_uses_arin(self):
        plugin = WhoisPlugin()
        with patch.object(plugin, "_whois_query", new_callable=AsyncMock, return_value="NetRange: 10.0.0.0 - 10.0.0.255"):
            result = await plugin.run("10.0.0.1")
        assert result["type"] == "ip"


# ── BannerGrabPlugin ────────────────────────────────────────────────────


class TestBannerGrabPluginValidateTarget:
    """Tests for BannerGrabPlugin.validate_target()."""

    def test_accepts_valid_ipv4(self):
        plugin = BannerGrabPlugin()
        for ip in ["192.168.1.1", "10.0.0.1", "8.8.8.8"]:
            assert plugin.validate_target(ip) is True

    def test_accepts_valid_hostnames(self):
        plugin = BannerGrabPlugin()
        for h in ["localhost", "example.com", "my-host.com"]:
            assert plugin.validate_target(h) is True

    def test_rejects_empty_string(self):
        assert BannerGrabPlugin().validate_target("") is False

    def test_rejects_special_characters(self):
        assert BannerGrabPlugin().validate_target("!@#$%") is False


@pytest.mark.asyncio
class TestBannerGrabPluginRun:
    """Tests for BannerGrabPlugin.run()."""

    async def test_run_returns_required_keys(self):
        plugin = BannerGrabPlugin()
        with patch("mapsec.plugins.banner_grab.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            with patch("mapsec.plugins.banner_grab.asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError):
                result = await plugin.run("10.0.0.1")
        assert "target" in result
        assert "ip" in result
        assert "banners" in result
        assert "total_banners" in result
        assert isinstance(result["banners"], list)

    async def test_run_grabs_http_banner(self):
        plugin = BannerGrabPlugin()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=(
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/8.1\r\n\r\n"
        ))
        mock_writer = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        with patch("mapsec.plugins.banner_grab.socket.getaddrinfo") as mock_gai, \
             patch("mapsec.plugins.banner_grab.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_gai.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            async def _open(host, port):
                if port == 80:
                    return (mock_reader, mock_writer)
                raise ConnectionRefusedError()
            mock_conn.side_effect = _open
            result = await plugin.run("10.0.0.1")

        http_banners = [b for b in result["banners"] if b["port"] == 80]
        assert len(http_banners) == 1
        assert "nginx" in http_banners[0].get("banner", "")
        assert "headers" in http_banners[0]

    async def test_run_handles_no_open_ports(self):
        plugin = BannerGrabPlugin()
        with patch("mapsec.plugins.banner_grab.socket.getaddrinfo") as mock_gai, \
             patch("mapsec.plugins.banner_grab.asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError):
            mock_gai.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            result = await plugin.run("10.0.0.1")
        assert result["total_banners"] == 0


# ═══════════════════════════════════════════════════════════════════
# SslCheckPlugin Tests
# ═══════════════════════════════════════════════════════════════════


class TestSslCheckPlugin:
    """Tests for the SslCheckPlugin."""

    def test_registration(self):
        from mapsec.core.plugin import get_plugins
        assert "ssl" in get_plugins()

    def test_validate_target_ip(self):
        plugin = SslCheckPlugin()
        assert plugin.validate_target("192.168.1.1") is True

    def test_validate_target_hostname(self):
        plugin = SslCheckPlugin()
        assert plugin.validate_target("example.com") is True

    def test_validate_target_invalid(self):
        plugin = SslCheckPlugin()
        assert plugin.validate_target("-invalid") is False

    @pytest.mark.asyncio
    async def test_run_connection_refused(self):
        plugin = SslCheckPlugin()
        with patch("mapsec.plugins.ssl_check.socket.create_connection", side_effect=ConnectionRefusedError):
            result = await plugin.run("10.0.0.1")
        assert "target" in result
        assert "certificate" in result
        assert "protocol" in result
        assert "cipher" in result
        assert "warnings" in result
        assert len(result["warnings"]) > 0

    @pytest.mark.asyncio
    async def test_run_successful_ssl(self):
        plugin = SslCheckPlugin()
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2024 GMT",
            "serialNumber": "03AB",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        mock_ssock = Mock()
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", 256, 256)
        mock_ssock.__enter__ = Mock(return_value=mock_ssock)
        mock_ssock.__exit__ = Mock(return_value=False)

        with patch("mapsec.plugins.ssl_check.socket.create_connection"), \
             patch("mapsec.plugins.ssl_check.ssl.SSLContext") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock
            result = await plugin.run("example.com")

        assert result["target"] == "example.com"
        assert result["protocol"]["version"] == "TLSv1.3"
        assert result["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
        assert result["cipher"]["bits"] == 256
        assert result["certificate"]["subject"] == "example.com"
        assert result["certificate"]["issuer"] == "Let's Encrypt"
        assert "example.com" in result["certificate"]["san"]

    @pytest.mark.asyncio
    async def test_run_weak_protocol_detected(self):
        plugin = SslCheckPlugin()
        mock_cert = {
            "subject": ((("commonName", "test.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
        }
        mock_ssock = Mock()
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.cipher.return_value = ("AES256-SHA256", 256, 256)
        mock_ssock.__enter__ = Mock(return_value=mock_ssock)
        mock_ssock.__exit__ = Mock(return_value=False)

        with patch("mapsec.plugins.ssl_check.socket.create_connection"), \
             patch("mapsec.plugins.ssl_check.ssl.SSLContext") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock

            async def fake_weak(host, port):
                return ["TLSv1"]
            with patch.object(plugin, "_detect_weak_protocols", side_effect=fake_weak):
                result = await plugin.run("test.com")

        assert "TLSv1" in result["protocol"]["weak_protocols"]
        assert any("weak protocol" in w.lower() for w in result["warnings"])


# ═══════════════════════════════════════════════════════════════════
# HttpHeadersPlugin Tests
# ═══════════════════════════════════════════════════════════════════


class TestHttpHeadersPlugin:
    """Tests for the HttpHeadersPlugin."""

    def test_registration(self):
        from mapsec.core.plugin import get_plugins
        assert "headers" in get_plugins()

    def test_validate_target_ip(self):
        plugin = HttpHeadersPlugin()
        assert plugin.validate_target("192.168.1.1") is True

    def test_validate_target_hostname(self):
        plugin = HttpHeadersPlugin()
        assert plugin.validate_target("example.com") is True

    def test_validate_target_invalid(self):
        plugin = HttpHeadersPlugin()
        assert plugin.validate_target("-bad") is False

    @pytest.mark.asyncio
    async def test_run_connection_error(self):
        plugin = HttpHeadersPlugin()
        with patch.object(plugin, "_fetch_headers", return_value=("", 0, {})):
            result = await plugin.run("10.0.0.1")
        assert "target" in result
        assert "url" in result
        assert result["status_code"] == 0
        assert "headers" in result
        assert "score" in result

    @pytest.mark.asyncio
    async def test_run_successful_with_headers(self):
        plugin = HttpHeadersPlugin()
        mock_headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "server": "nginx/1.18.0",
        }
        with patch.object(plugin, "_make_request", return_value=(200, mock_headers)):
            result = await plugin.run("example.com")

        assert result["target"] == "example.com"
        assert result["status_code"] == 200
        assert "score" in result
        assert "grade" in result["score"]
        assert result["score"]["grade"] in ("A", "B", "C", "D", "F")

    @pytest.mark.asyncio
    async def test_run_detects_leaked_headers(self):
        plugin = HttpHeadersPlugin()
        mock_headers = {
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4",
        }
        with patch.object(plugin, "_make_request", return_value=(200, mock_headers)):
            result = await plugin.run("example.com")

        assert "Server" in result["leaked_headers"]
        assert "X-Powered-By" in result["leaked_headers"]


# ── ShodanPlugin ─────────────────────────────────────────────────────


class TestShodanPluginRegistration:
    def test_shodan_registered(self):
        from mapsec.core.plugin import get_plugins
        assert "shodan" in get_plugins()

    def test_shodan_name_and_description(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        p = ShodanPlugin()
        assert p.name == "shodan"
        assert "Shodan" in p.description


class TestShodanPluginValidateTarget:
    def test_validates_ip(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        assert ShodanPlugin().validate_target("8.8.8.8") is True

    def test_validates_domain(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        assert ShodanPlugin().validate_target("example.com") is True

    def test_rejects_empty(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        assert ShodanPlugin().validate_target("") is False

    def test_rejects_garbage(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        assert ShodanPlugin().validate_target("not a target!") is False


class TestShodanPluginRun:
    @pytest.mark.asyncio
    async def test_run_no_api_key(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        import os
        old = os.environ.pop("SHODAN_API_KEY", None)
        try:
            result = await ShodanPlugin().run("8.8.8.8")
            assert "error" in result
        finally:
            if old:
                os.environ["SHODAN_API_KEY"] = old

    @pytest.mark.asyncio
    async def test_run_api_error(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        import os
        os.environ["SHODAN_API_KEY"] = "test_key_12345"
        try:
            plugin = ShodanPlugin()
            with patch.object(plugin, "_fetch_url", side_effect=Exception("Connection refused")):
                result = await plugin.run("8.8.8.8")
            assert "error" in result
        finally:
            os.environ.pop("SHODAN_API_KEY", None)

    @pytest.mark.asyncio
    async def test_run_successful(self):
        from mapsec.plugins.shodan_lookup import ShodanPlugin
        import json
        import os
        os.environ["SHODAN_API_KEY"] = "test_key_12345"
        try:
            plugin = ShodanPlugin()
            mock_response = json.dumps({
                "ip_str": "8.8.8.8",
                "org": "Google LLC",
                "isp": "Google LLC",
                "os": None,
                "country_name": "United States",
                "city": "Mountain View",
                "lat": 37.4056,
                "lon": -122.0775,
                "ports": [53, 443],
                "hostnames": ["dns.google"],
                "vulns": {"CVE-2021-44228": {"cvss": 10.0}},
                "data": [
                    {"port": 53, "product": "Google DNS", "version": "", "transport": "udp"},
                    {"port": 443, "product": "nginx", "version": "1.18.0", "transport": "tcp"},
                ],
            })
            with patch.object(plugin, "_fetch_url", return_value=mock_response):
                result = await plugin.run("8.8.8.8")
            assert result["ip"] == "8.8.8.8"
            assert result["org"] == "Google LLC"
            assert 53 in result["ports"]
            assert len(result["services"]) == 2
            assert "CVE-2021-44228" in result["vulns"]
        finally:
            os.environ.pop("SHODAN_API_KEY", None)


# ── CveLookupPlugin ──────────────────────────────────────────────────


class TestCvePluginRegistration:
    def test_cve_registered(self):
        from mapsec.core.plugin import get_plugins
        assert "cve" in get_plugins()

    def test_cve_name_and_description(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        p = CveLookupPlugin()
        assert p.name == "cve"
        assert "CVE" in p.description


class TestCvePluginRun:
    @pytest.mark.asyncio
    async def test_run_no_context(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        result = await CveLookupPlugin().run("192.168.1.1")
        assert "software_found" in result
        assert result["software_found"] == []

    @pytest.mark.asyncio
    async def test_run_with_nmap_context_no_products(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        context = {"nmap": {"hosts": [{"ports": [{"port": 80, "service": {"name": "http", "product": "", "version": ""}}]}]}}
        result = await CveLookupPlugin().run("192.168.1.1", context=context)
        assert result["software_found"] == []

    @pytest.mark.asyncio
    async def test_run_extracts_from_nmap(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        context = {
            "nmap": {"hosts": [{"ports": [
                {"port": 22, "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"}},
            ]}]},
        }
        plugin = CveLookupPlugin()
        with patch.object(plugin, "_query_nvd", return_value=[]):
            result = await plugin.run("192.168.1.1", context=context)
        assert len(result["software_found"]) == 1
        assert "openssh" in result["software_found"][0]["product"].lower()

    @pytest.mark.asyncio
    async def test_run_extracts_from_banner(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        context = {
            "banner": {"banners": [
                {"port": 80, "banner": "nginx/1.18.0"},
            ]},
        }
        plugin = CveLookupPlugin()
        with patch.object(plugin, "_query_nvd", return_value=[]):
            result = await plugin.run("192.168.1.1", context=context)
        assert len(result["software_found"]) >= 1

    def test_validate_target_always_true(self):
        from mapsec.plugins.cve_lookup import CveLookupPlugin
        assert CveLookupPlugin().validate_target("anything") is True


# ═══════════════════════════════════════════════════════════════════
# ExploitAdvisor Tests
# ═══════════════════════════════════════════════════════════════════


class TestExploitAdvisor:
    """Tests for the ExploitAdvisor service — template and LLM modes."""

    # ------------------------------------------------------------------
    # Template matching (no LLM)
    # ------------------------------------------------------------------

    def test_template_xss(self):
        """CVE with 'XSS' in description matches xss template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
            "description": "Cross-Site Scripting (XSS) in search functionality",
            "product": "WebApp", "version": "1.0",
        }]
        result = advisor.analyze(cves)
        assert len(result) == 1
        assert "XSS" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_sql_injection(self):
        """CVE with 'SQL injection' in description matches sql_injection template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0002", "score": 9.0, "severity": "critical",
            "description": "SQL injection vulnerability in login form",
            "product": "DBApp", "version": "2.0",
        }]
        result = advisor.analyze(cves)
        assert "SQL Injection" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_rce(self):
        """CVE with 'remote code execution' in description matches rce template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0003", "score": 10.0, "severity": "critical",
            "description": "Remote code execution in file parser",
            "product": "CoreLib", "version": "1.5",
        }]
        result = advisor.analyze(cves)
        assert "Remote Code Execution" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_command_injection(self):
        """CVE with 'command injection' in description matches command_injection template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0004", "score": 8.0, "severity": "high",
            "description": "Command injection in file upload endpoint",
            "product": "UploadSvc", "version": "3.0",
        }]
        result = advisor.analyze(cves)
        assert "Command Injection" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_path_traversal(self):
        """CVE with 'path traversal' in description matches path_traversal template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0005", "score": 6.5, "severity": "medium",
            "description": "Path traversal vulnerability in download feature",
            "product": "FileSrv", "version": "1.0",
        }]
        result = advisor.analyze(cves)
        assert "Traversal" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_lfi(self):
        """CVE with 'local file inclusion' in description matches lfi template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0006", "score": 7.0, "severity": "high",
            "description": "Local file inclusion via insecure parameter",
            "product": "CMS", "version": "2.1",
        }]
        result = advisor.analyze(cves)
        assert "Local File Inclusion" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_sqli(self):
        """CVE with 'sqli' keyword (case-insensitive) matches sql_injection template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0007", "score": 9.0, "severity": "critical",
            "description": "SQLi in search parameter allows data extraction",
            "product": "SearchApp", "version": "1.0",
        }]
        result = advisor.analyze(cves)
        assert "SQL Injection" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_no_match(self):
        """Generic CVE with no known keywords falls back to default (rce) template."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0008", "score": 5.0, "severity": "medium",
            "description": "A generic security vulnerability in module X",
            "product": "GenericApp", "version": "1.0",
        }]
        result = advisor.analyze(cves)
        # Default fallback is the rce template
        assert "Remote Code Execution" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_template_multiple_cves(self):
        """Multiple CVEs with different keywords are each matched correctly."""
        advisor = ExploitAdvisor()
        cves = [
            {"id": "CVE-2024-0010", "score": 7.5, "severity": "high",
             "description": "XSS in search", "product": "P1", "version": "1.0"},
            {"id": "CVE-2024-0011", "score": 9.0, "severity": "critical",
             "description": "SQL injection in login", "product": "P2", "version": "2.0"},
            {"id": "CVE-2024-0012", "score": 5.0, "severity": "medium",
             "description": "Generic bug with no keywords", "product": "P3", "version": "3.0"},
        ]
        result = advisor.analyze(cves)
        assert len(result) == 3
        assert "XSS" in result[0]["title"]
        assert "SQL Injection" in result[1]["title"]
        assert "Remote Code Execution" in result[2]["title"]  # default fallback

    def test_template_empty_cves(self):
        """Empty CVE list returns empty list in template mode."""
        advisor = ExploitAdvisor()
        result = advisor.analyze([])
        assert result == []

    def test_template_severity_ordering(self):
        """Output preserves input order — critical CVEs come before info CVEs."""
        advisor = ExploitAdvisor()
        cves = [
            {"id": "CVE-2024-0020", "score": 9.5, "severity": "critical",
             "description": "RCE in core", "product": "App", "version": "1.0"},
            {"id": "CVE-2024-0021", "score": 5.0, "severity": "medium",
             "description": "XSS in search", "product": "App", "version": "1.0"},
            {"id": "CVE-2024-0022", "score": 2.0, "severity": "info",
             "description": "Information leak in debug mode", "product": "App", "version": "1.0"},
        ]
        result = advisor.analyze(cves)
        assert len(result) == 3
        assert result[0]["severity"] == "critical"
        assert result[1]["severity"] == "medium"
        assert result[2]["severity"] == "info"

    # ------------------------------------------------------------------
    # LLM mode (mocked)
    # ------------------------------------------------------------------

    def test_llm_success(self):
        """LLM returns valid JSON — exploits parsed correctly with source='llm'."""
        mock_provider = MagicMock()
        mock_provider.api_key = "test-key"
        mock_provider.model = "test-model"
        advisor = ExploitAdvisor(llm_provider=mock_provider)

        llm_response = json.dumps([
            {
                "cve_id": "CVE-2024-0001",
                "exploit_scenario": "The attacker sends a crafted payload to exploit the buffer overflow",
                "impact": "Full system compromise",
            }
        ])

        with patch.object(advisor, "_call_llm", return_value=llm_response):
            cves = [{
                "id": "CVE-2024-0001", "score": 9.5, "severity": "critical",
                "description": "Buffer overflow in network daemon",
                "product": "NetSvc", "version": "1.0",
            }]
            result = advisor.analyze(cves)

        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-0001"
        assert result[0]["severity"] == "critical"
        assert result[0]["score"] == 9.5
        assert result[0]["exploit_scenario"] == (
            "The attacker sends a crafted payload to exploit the buffer overflow"
        )
        assert result[0]["impact"] == "Full system compromise"
        assert result[0]["source"] == "llm"

    def test_llm_markdown_fences(self):
        """LLM response wrapped in ```json fences is still parsed correctly."""
        mock_provider = MagicMock()
        mock_provider.api_key = "test-key"
        mock_provider.model = "test-model"
        advisor = ExploitAdvisor(llm_provider=mock_provider)

        llm_response = """Here is the exploit analysis:
```json
[
    {"cve_id": "CVE-2024-0001", "exploit_scenario": "XSS attack via form input", "impact": "Session hijacking"}
]
```
"""

        with patch.object(advisor, "_call_llm", return_value=llm_response):
            cves = [{
                "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
                "description": "XSS vulnerability", "product": "WebApp", "version": "2.0",
            }]
            result = advisor.analyze(cves)

        assert len(result) == 1
        assert result[0]["source"] == "llm"
        assert "XSS attack" in result[0]["exploit_scenario"]

    def test_llm_invalid_response(self):
        """LLM returns garbage JSON — falls back to template mode."""
        mock_provider = MagicMock()
        mock_provider.api_key = "test-key"
        mock_provider.model = "test-model"
        advisor = ExploitAdvisor(llm_provider=mock_provider)

        with patch.object(advisor, "_call_llm", return_value="This is not JSON at all"):
            cves = [{
                "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
                "description": "XSS in search", "product": "WebApp", "version": "1.0",
            }]
            result = advisor.analyze(cves)

        # Falls back to template matching
        assert result[0]["source"] == "template"
        assert "XSS" in result[0]["title"]

    def test_llm_http_error(self):
        """LLM HTTP request fails (_call_llm returns None) — falls back to templates."""
        mock_provider = MagicMock()
        mock_provider.api_key = "test-key"
        mock_provider.model = "test-model"
        advisor = ExploitAdvisor(llm_provider=mock_provider)

        with patch.object(advisor, "_call_llm", return_value=None):
            cves = [{
                "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
                "description": "XSS in search", "product": "WebApp", "version": "1.0",
            }]
            result = advisor.analyze(cves)

        assert result[0]["source"] == "template"

    def test_llm_none_provider(self):
        """No LLM provider configured — templates used exclusively."""
        advisor = ExploitAdvisor(llm_provider=None)
        cves = [{
            "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
            "description": "XSS in search", "product": "WebApp", "version": "1.0",
        }]
        result = advisor.analyze(cves)
        assert result[0]["source"] == "template"
        # Verify _call_llm is never invoked when LLM is absent
        with patch.object(advisor, "_call_llm", side_effect=RuntimeError("should not be called")):
            result2 = advisor.analyze(cves)
        assert result2[0]["source"] == "template"

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_no_cves_empty(self):
        """Empty CVE list with LLM configured still returns empty list immediately."""
        mock_provider = MagicMock()
        mock_provider.api_key = "test-key"
        mock_provider.model = "test-model"
        advisor = ExploitAdvisor(llm_provider=mock_provider)

        # Patch to verify LLM is never called for empty input
        with patch.object(advisor, "_call_llm", side_effect=RuntimeError("should not be called")):
            result = advisor.analyze([])

        assert result == []

    def test_cve_missing_description(self):
        """CVE dict missing 'description' field — empty string used, default template applied."""
        advisor = ExploitAdvisor()
        cves = [{
            "id": "CVE-2024-0001", "score": 7.5, "severity": "high",
            "product": "App", "version": "1.0",
            # no "description" key
        }]
        result = advisor.analyze(cves)
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-0001"
        # Empty description matches no keywords → default (rce) template
        assert "Remote Code Execution" in result[0]["title"]
        assert result[0]["source"] == "template"

    def test_cve_missing_id(self):
        """CVE dict missing 'id' field — defaults to empty string."""
        advisor = ExploitAdvisor()
        cves = [{
            "score": 7.5, "severity": "high",
            "description": "XSS vulnerability in product",
            "product": "App", "version": "1.0",
            # no "id" key
        }]
        result = advisor.analyze(cves)
        assert len(result) == 1
        assert result[0]["cve_id"] == ""
        assert result[0]["source"] == "template"
