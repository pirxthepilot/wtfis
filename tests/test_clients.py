import json
from unittest.mock import MagicMock, patch

import pytest
from shodan import APIError

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.base import requests
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import Shodan, ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.ipwhois import IpWhoisMap


@pytest.fixture()
def abuseipdb_client():
    return AbuseIpDbClient("dummykey")


@pytest.fixture()
def greynoise_client():
    return GreynoiseClient("dummykey")


@pytest.fixture()
def ip2whois_client():
    return Ip2WhoisClient("dummykey")


@pytest.fixture()
def ipwhois_client():
    return IpWhoisClient()


@pytest.fixture()
def shodan_client():
    return ShodanClient("dummykey")


@pytest.fixture()
def urlhaus_client():
    return UrlHausClient()


@pytest.fixture()
def virustotal_client():
    return VTClient("dummykey")


class TestAbuseIpDbClient:
    def test_init(self, abuseipdb_client):
        assert abuseipdb_client.name == "AbuseIPDB"
        assert abuseipdb_client.api_key == "dummykey"

    @patch.object(requests.Session, "get")
    def test_enrich_ips(self, mock_requests_get, test_data, abuseipdb_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(
            test_data("abuseipdb_1.1.1.1_raw.json")
        )
        mock_requests_get.return_value = mock_resp

        abuseipdb = abuseipdb_client.enrich_ips("thisdoesntmatter").root["1.1.1.1"]

        assert abuseipdb.ip_address == "1.1.1.1"
        assert abuseipdb.abuse_confidence_score == 100
        assert abuseipdb.usage_type == "Data Center/Web Hosting/Transit"
        assert abuseipdb.total_reports == 567
        assert abuseipdb.num_distinct_users == 123


class TestIp2WhoisClient:
    def test_init(self, ip2whois_client):
        assert ip2whois_client.api_key == "dummykey"
        assert ip2whois_client.name == "IP2Whois"

    @patch.object(requests.Session, "get")
    def test_get_whois(self, mock_requests_get, test_data, ip2whois_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(
            test_data("ip2whois_whois_hotmail.json")
        )
        mock_requests_get.return_value = mock_resp

        whois = ip2whois_client.get_whois("thisdoesntmatter")

        assert whois.domain == "hotmail.com"

    @patch.object(requests.Session, "get")
    def test_get_whois_http_error(self, mock_requests_get, ip2whois_client):
        mock_resp = requests.models.Response()

        with patch.object(mock_resp, "json") as mock_resp_json:
            # 404 - no exception
            mock_resp.status_code = 404
            mock_resp_json.return_value = {"error": {"error_code": 10006}}
            mock_requests_get.return_value = mock_resp
            assert ip2whois_client.get_whois("thisdoesntmatter").source == "ip2whois"

            # 400 - no exception
            mock_resp.status_code = 400
            mock_resp_json.return_value = {"error": {"error_code": 10007}}
            mock_requests_get.return_value = mock_resp
            assert ip2whois_client.get_whois("thisdoesntmatter").source == "ip2whois"

            # 400 - with exception
            mock_resp.status_code = 400
            mock_resp_json.return_value = {"error": {"error_code": 10008}}
            mock_requests_get.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError) as err:
                ip2whois_client.get_whois("thisdoesntmatter")
            assert err.value.response.json()["error"]["error_code"] == 10008


class TestGreynoiseClient:
    def test_init(self, greynoise_client):
        assert greynoise_client.name == "Greynoise"
        assert greynoise_client.api_key == "dummykey"


class TestIpWhoisClient:
    def test_init(self, ipwhois_client):
        assert ipwhois_client.name == "IPWhois"

    @patch.object(requests.Session, "get")
    def test_get_ipwhois(self, mock_requests_get, test_data, ipwhois_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(test_data("ipwhois_raw_10.0.0.1.json"))
        mock_requests_get.return_value = mock_resp

        whois = ipwhois_client.enrich_ips("thisdoesntmatter")

        assert whois == IpWhoisMap.model_validate({})


class TestShodanClient:
    def test_init(self, shodan_client):
        assert shodan_client.s.api_key == "dummykey"
        assert shodan_client.name == "Shodan"

    @patch.object(Shodan, "host")
    def test_get_ip_apierror_invalid_key(self, mock_shodan_host, shodan_client):
        """Test invalid API key APIError"""
        mock_shodan_host.side_effect = APIError("Invalid API key")

        with pytest.raises(APIError) as e:
            shodan_client.enrich_ips("thisdoesntmatter")

        assert e.type == APIError
        assert str(e.value) == "Invalid API key"

    @patch.object(Shodan, "host")
    def test_get_ip_apierror_other(self, mock_shodan_host, shodan_client):
        """Test other invalid API key APIError"""
        mock_shodan_host.side_effect = APIError("Some other error")

        with pytest.raises(APIError) as e:
            shodan_client.enrich_ips("thisdoesntmatter")

        assert e.type == APIError
        assert str(e.value) == "Some other error"


class TestUrlhausClient:
    def test_init(self, urlhaus_client):
        assert urlhaus_client.name == "URLhaus"

    @patch.object(requests.Session, "post")
    def test_enrich_ips(self, mock_requests_post, test_data, urlhaus_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(test_data("urlhaus_1.1.1.1.json"))[
            "1.1.1.1"
        ]
        mock_requests_post.return_value = mock_resp

        urlhaus = urlhaus_client.enrich_ips("thisdoesntmatter").root["1.1.1.1"]

        assert urlhaus.host == "1.1.1.1"
        assert urlhaus.url_count == 10
        assert urlhaus.urlhaus_reference == "https://urlhaus.abuse.ch/host/1.1.1.1/"


class TestVirustotalClient:
    def test_init(self, virustotal_client):
        assert virustotal_client.s.headers["x-apikey"] == "dummykey"
        assert virustotal_client.s.headers["Accept"] == "application/json"
        assert virustotal_client.name == "Virustotal"

    @patch.object(requests.Session, "get")
    def test_get_whois_domain(self, mock_requests_get, test_data, virustotal_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(test_data("vt_whois_gist.json"))
        mock_requests_get.return_value = mock_resp

        whois = virustotal_client.get_whois("gist.github.com")

        assert whois.domain == "github.com"
        assert whois.registrar == "MarkMonitor Inc."

    @patch.object(requests.Session, "get")
    def test_get_whois_ip(self, mock_requests_get, test_data, virustotal_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(test_data("vt_whois_1.1.1.1.json"))
        mock_requests_get.return_value = mock_resp

        whois = virustotal_client.get_whois("1.1.1.1")

        assert whois.domain == "one.one"
        assert whois.registrar == "One.com A/S - ONE"
