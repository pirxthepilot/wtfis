import json
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError
from rich.console import Console

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.base import requests
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.virustotal import Resolutions


def generate_domain_handler(max_resolutions=3):
    return DomainHandler(
        entity="www.example[.]com",
        console=Console(),
        progress=MagicMock(),
        vt_client=VTClient("dummykey"),
        ip_geoasn_client=IpWhoisClient(),
        whois_client=Ip2WhoisClient("dummykey"),
        shodan_client=ShodanClient("dummykey"),
        greynoise_client=GreynoiseClient("dummykey"),
        abuseipdb_client=AbuseIpDbClient("dummykey"),
        urlhaus_client=UrlHausClient(),
        max_resolutions=max_resolutions,
    )


def generate_ip_handler():
    return IpAddressHandler(
        entity="1[.]1[.]1[.]1",
        console=Console(),
        progress=MagicMock(),
        vt_client=VTClient("dummykey"),
        ip_geoasn_client=IpWhoisClient(),
        whois_client=Ip2WhoisClient("dummykey"),
        shodan_client=ShodanClient("dummykey"),
        greynoise_client=GreynoiseClient("dummykey"),
        abuseipdb_client=AbuseIpDbClient("dummykey"),
        urlhaus_client=UrlHausClient(),
    )


@pytest.fixture
def domain_handler():
    return generate_domain_handler


@pytest.fixture
def ip_handler():
    return generate_ip_handler


class TestDomainHandler:
    def test_entity_refang(self, domain_handler):
        handler = domain_handler()
        assert handler.entity == "www.example.com"

    def test_fetch_data_1(self, domain_handler, test_data):
        """Test with max_resolutions = 3 (default)"""
        handler = domain_handler()
        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        handler._fetch_vt_domain = MagicMock()
        handler._fetch_vt_resolutions = MagicMock()
        handler._fetch_geoasn = MagicMock()
        handler._fetch_whois = MagicMock()
        handler._fetch_shodan = MagicMock()
        handler._fetch_greynoise = MagicMock()
        handler._fetch_urlhaus = MagicMock()

        handler.fetch_data()
        handler._fetch_vt_domain.assert_called_once()
        handler._fetch_vt_resolutions.assert_called_once()
        handler._fetch_geoasn.assert_called_once()
        handler._fetch_whois.assert_called_once()
        handler._fetch_shodan.assert_called_once()
        handler._fetch_greynoise.assert_called_once()
        handler._fetch_urlhaus.assert_called_once()

    def test_fetch_data_2(self, domain_handler):
        """Test with max_resolutions = 0"""
        handler = domain_handler(0)
        handler._fetch_vt_domain = MagicMock()
        handler._fetch_vt_resolutions = MagicMock()
        handler._fetch_geoasn = MagicMock()
        handler._fetch_whois = MagicMock()
        handler._fetch_shodan = MagicMock()
        handler._fetch_greynoise = MagicMock()
        handler._fetch_urlhaus = MagicMock()

        handler.fetch_data()
        handler._fetch_vt_domain.assert_called_once()
        handler._fetch_vt_resolutions.assert_not_called()
        handler._fetch_geoasn.assert_not_called()
        handler._fetch_whois.assert_called_once()
        handler._fetch_shodan.assert_not_called()
        handler._fetch_greynoise.assert_not_called()
        handler._fetch_urlhaus.assert_called_once()

        assert handler.geoasn == IpWhoisMap.model_validate({})
        assert handler.geoasn.root == {}

    @patch.object(requests.Session, "get")
    def test_vt_http_error(self, mock_requests_get, domain_handler, capsys):
        """
        Test a requests HTTPError from the VT client. This also tests the
        common_exception_handler decorator.
        """
        handler = domain_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 401
        mock_requests_get.return_value = mock_resp

        # Thorough test of first _fetch_* method
        with pytest.raises(SystemExit) as e:
            handler._fetch_vt_domain()

        capture = capsys.readouterr()

        assert (
            capture.err == "Error fetching data: 401 Client Error: None for url: None\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 1

        # Extra: just make sure program exits correctly
        with pytest.raises(SystemExit) as e:
            handler._fetch_vt_resolutions()
        assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_vt_validation_error(self, mock_requests_get, domain_handler, capsys):
        """
        Test a pydantic data model ValidationError from the VT client. This also tests
        the common_exception_handler decorator.
        """
        handler = domain_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {"intentionally": "wrong data"}
            mock_requests_get.return_value = mock_resp

            # Thorough test of first _fetch_* method
            with pytest.raises(SystemExit) as e:
                handler._fetch_vt_domain()

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 1 validation error for Domain\ndata\n"
                "  Field required [type=missing, input_value={'intentionally': "
                "'wrong data'}, input_type=dict]\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

            # Extra: just make sure program exits correctly
            with pytest.raises(SystemExit) as e:
                handler._fetch_vt_resolutions()
            assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_ipwhois_http_error(
        self, mock_requests_get, domain_handler, capsys, test_data
    ):
        handler = domain_handler()
        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        mock_resp = requests.models.Response()

        mock_resp.status_code = 500
        mock_requests_get.return_value = mock_resp

        handler._fetch_geoasn(*["1.2.3.4", "1.2.3.5"])
        assert handler.warnings[0].startswith(
            "Could not fetch IPWhois: 500 Server Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch IPWhois: 500 Server Error:"
        )

    @patch.object(requests.Session, "get")
    def test_ipwhois_validation_error(self, mock_requests_get, domain_handler, capsys):
        handler = domain_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {
                "success": True,
                "intentionally": "wrong data",
            }
            mock_requests_get.return_value = mock_resp

            with pytest.raises(SystemExit) as e:
                handler._fetch_geoasn("1.2.3.4")

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 9 validation errors for IpWhois\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_whois_http_error(self, mock_requests_get, domain_handler, capsys):
        handler = domain_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 401
        mock_requests_get.return_value = mock_resp

        handler._fetch_whois()
        assert handler.warnings[0].startswith(
            "Could not fetch IP2Whois: 401 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch IP2Whois: 401 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_vt_resolutions_429_error(self, mock_requests_get, domain_handler, capsys):
        """
        Test fail open behavior of VT resolution fetching when rate limited
        """
        handler = domain_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 429
        mock_requests_get.return_value = mock_resp

        handler._fetch_vt_resolutions()
        assert handler.warnings[0].startswith(
            "Could not fetch Virustotal resolutions: 429 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Virustotal resolutions: 429 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_whois_429_error(self, mock_requests_get, domain_handler, capsys):
        """
        Test fail open behavior of whois fetching when rate limited
        Since _fetch_whois() is in the base class, this should also cover the
        IpAddressHandler use case.
        """
        handler = domain_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 429
        mock_requests_get.return_value = mock_resp

        handler._fetch_whois()
        assert handler.warnings[0].startswith(
            "Could not fetch IP2Whois: 429 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch IP2Whois: 429 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_429_error(
        self, mock_requests_get, domain_handler, capsys, test_data
    ):
        """
        Test fail open behavior of Greynoise when rate limited
        """
        handler = domain_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 429
        mock_requests_get.return_value = mock_resp

        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        handler._fetch_greynoise(*["1.2.3.4", "1.2.3.5"])
        assert handler.warnings[0].startswith(
            "Could not fetch Greynoise: 429 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: 429 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_404_error(self, mock_requests_get, domain_handler, test_data):
        """
        Test fail open behavior of Greynoise when no IP found (404) and no warning
        message
        """
        handler = domain_handler(3)
        mock_resp = requests.models.Response()

        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        mock_resp.status_code = 404
        mock_requests_get.return_value = mock_resp

        handler._fetch_greynoise(*["1.2.3.4", "1.2.3.5"])
        assert len(handler.warnings) == 0
        assert handler.greynoise == GreynoiseIpMap.model_validate({})

    @patch.object(requests.Session, "get")
    def test_greynoise_403_error(
        self, mock_requests_get, domain_handler, test_data, capsys
    ):
        """
        Test exception behavior of Greynoise when not under any of the handled cases
        """
        handler = domain_handler(3)
        mock_resp = requests.models.Response()

        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        mock_resp.status_code = 403
        mock_requests_get.return_value = mock_resp

        handler._fetch_greynoise(*["1.2.3.4", "1.2.3.5"])
        assert handler.warnings[0].startswith(
            "Could not fetch Greynoise: 403 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: 403 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_connection_error(
        self, mock_requests_get, domain_handler, test_data, capsys
    ):
        """
        Test exception behavior of Greynoise with non-HTTPError requests exception
        """
        handler = domain_handler(3)
        mock_requests_get.side_effect = ConnectionError("Foo bar message")

        handler.resolutions = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        handler._fetch_greynoise(*["1.2.3.4", "1.2.3.5"])
        assert handler.warnings[0] == "Could not fetch Greynoise: Foo bar message"

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: Foo bar message"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_validation_error(
        self, mock_requests_get, domain_handler, capsys
    ):
        handler = domain_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {"intentionally": "wrong data"}
            mock_requests_get.return_value = mock_resp

            with pytest.raises(SystemExit) as e:
                handler._fetch_greynoise("1.2.3.4")

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 5 validation errors for GreynoiseIp\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

    @patch.object(requests.Session, "post")
    def test_urlhaus_http_error(self, mock_requests_post, domain_handler, capsys):
        """
        Test exception behavior of URLhaus with non-HTTPError requests exception
        """
        handler = domain_handler()
        mock_requests_post.side_effect = ConnectionError("Foo bar message")

        handler._fetch_urlhaus()
        assert handler.warnings[0] == "Could not fetch URLhaus: Foo bar message"

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith("WARN: Could not fetch URLhaus: Foo bar message")


class TestIpAddressHandler:
    def test_entity_refang(self, ip_handler):
        handler = ip_handler()
        assert handler.entity == "1.1.1.1"

    def test_fetch_data(self, ip_handler):
        handler = ip_handler()
        handler._fetch_vt_ip_address = MagicMock()
        handler._fetch_geoasn = MagicMock()
        handler._fetch_whois = MagicMock()
        handler._fetch_shodan = MagicMock()
        handler._fetch_greynoise = MagicMock()
        handler._fetch_urlhaus = MagicMock()
        handler._fetch_abuseipdb = MagicMock()

        handler.fetch_data()
        handler._fetch_vt_ip_address.assert_called_once()
        handler._fetch_geoasn.assert_called_once()
        handler._fetch_whois.assert_called_once()
        handler._fetch_shodan.assert_called_once()
        handler._fetch_greynoise.assert_called_once()
        handler._fetch_urlhaus.assert_called_once()
        handler._fetch_abuseipdb.assert_called_once()

    @patch.object(requests.Session, "get")
    def test_vt_http_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 404
        mock_requests_get.return_value = mock_resp

        # Thorough test of first _fetch_* method
        with pytest.raises(SystemExit) as e:
            handler._fetch_vt_ip_address()

        capture = capsys.readouterr()

        assert (
            capture.err == "Error fetching data: 404 Client Error: None for url: None\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_vt_validation_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {"intentionally": "wrong data"}
            mock_requests_get.return_value = mock_resp

            # Thorough test of first _fetch_* method
            with pytest.raises(SystemExit) as e:
                handler._fetch_vt_ip_address()

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 1 validation error for IpAddress\ndata\n"
                "  Field required [type=missing, input_value={'intentionally': "
                "'wrong data'}, input_type=dict]\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_ipwhois_http_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()

        mock_resp = requests.models.Response()

        mock_resp.status_code = 502
        mock_requests_get.return_value = mock_resp

        handler._fetch_geoasn("1.2.3.4")
        assert handler.warnings[0].startswith(
            "Could not fetch IPWhois: 502 Server Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch IPWhois: 502 Server Error:"
        )

    @patch.object(requests.Session, "get")
    def test_whois_http_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 403
        mock_requests_get.return_value = mock_resp

        handler._fetch_whois()
        assert handler.warnings[0].startswith(
            "Could not fetch IP2Whois: 403 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch IP2Whois: 403 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_ipwhois_validation_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {
                "success": True,
                "intentionally": "wrong data",
            }
            mock_requests_get.return_value = mock_resp

            with pytest.raises(SystemExit) as e:
                handler._fetch_geoasn("1.2.3.4")

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 9 validation errors for IpWhois\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_shodan_api_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test fail open behavior of Shodan on invalid API key
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 401
        mock_resp._content = b"<html>"
        mock_requests_get.return_value = mock_resp

        handler._fetch_shodan("1.2.3.4")
        assert handler.warnings[0].startswith("Could not fetch Shodan: Invalid API key")

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith("WARN: Could not fetch Shodan: Invalid API key")

    @patch.object(requests.Session, "get")
    def test_greynoise_http_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test Greynoise HTTP error that results in a SystemExit
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 401
        mock_requests_get.return_value = mock_resp

        with pytest.raises(SystemExit) as e:
            handler._fetch_vt_ip_address()

        capture = capsys.readouterr()

        assert (
            capture.err == "Error fetching data: 401 Client Error: None for url: None\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 1

    @patch.object(requests.Session, "get")
    def test_greynoise_429_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test fail open behavior of Greynoise when rate limited
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 429
        mock_requests_get.return_value = mock_resp

        handler._fetch_greynoise("1.2.3.4")
        assert handler.warnings[0].startswith(
            "Could not fetch Greynoise: 429 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: 429 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_404_error(self, mock_requests_get, ip_handler):
        """
        Test fail open behavior of Greynoise when no IP found (404) and no warning
        message
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 404
        mock_requests_get.return_value = mock_resp

        handler._fetch_greynoise()
        assert len(handler.warnings) == 0
        assert handler.greynoise == GreynoiseIpMap.model_validate({})

    @patch.object(requests.Session, "get")
    def test_greynoise_403_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test exception behavior of Greynoise when not under any of the handled cases
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 403
        mock_requests_get.return_value = mock_resp

        handler._fetch_greynoise("1.2.3.4")
        assert handler.warnings[0].startswith(
            "Could not fetch Greynoise: 403 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: 403 Client Error:"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_connection_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test exception behavior of Greynoise with non-HTTPError requests exception
        """
        handler = ip_handler()
        mock_requests_get.side_effect = ConnectionError("Foo bar message")

        handler._fetch_greynoise("1.2.3.4")
        assert handler.warnings[0] == "Could not fetch Greynoise: Foo bar message"

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch Greynoise: Foo bar message"
        )

    @patch.object(requests.Session, "get")
    def test_greynoise_validation_error(self, mock_requests_get, ip_handler, capsys):
        handler = ip_handler()
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            mock_resp.status_code = 200
            mock_resp_json.return_value = {"intentionally": "wrong data"}
            mock_requests_get.return_value = mock_resp

            with pytest.raises(SystemExit) as e:
                handler._fetch_greynoise("1.2.3.4")

            capture = capsys.readouterr()

            assert capture.err.startswith(
                "Data model validation error: 5 validation errors for GreynoiseIp\n"
            )
            assert e.type == SystemExit
            assert e.value.code == 1

    @patch.object(requests.Session, "post")
    def test_urlhaus_http_error(self, mock_requests_post, ip_handler, capsys):
        """
        Test exception behavior of URLhaus with non-HTTPError requests exception
        """
        handler = ip_handler()
        mock_requests_post.side_effect = ConnectionError("Foo bar message")

        handler._fetch_urlhaus()
        assert handler.warnings[0] == "Could not fetch URLhaus: Foo bar message"

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith("WARN: Could not fetch URLhaus: Foo bar message")

    @patch.object(requests.Session, "get")
    def test_abuseipdb_429_error(self, mock_requests_get, ip_handler, capsys):
        """
        Test fail open behavior of AbuseIPDB when rate limited
        """
        handler = ip_handler()
        mock_resp = requests.models.Response()

        mock_resp.status_code = 429
        mock_requests_get.return_value = mock_resp

        handler._fetch_abuseipdb("1.2.3.4")
        assert handler.warnings[0].startswith(
            "Could not fetch AbuseIPDB: 429 Client Error:"
        )

        handler.print_warnings()
        capture = capsys.readouterr()
        assert capture.out.startswith(
            "WARN: Could not fetch AbuseIPDB: 429 Client Error:"
        )
