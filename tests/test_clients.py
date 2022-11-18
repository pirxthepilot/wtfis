import json
import pytest
from unittest.mock import MagicMock, patch

from wtfis.clients.base import requests
from wtfis.clients.ip2whois import Ip2WhoisClient


@pytest.fixture()
def ip2whois_client():
    return Ip2WhoisClient("dummykey")


class TestIp2WhoisClient:
    def test_init(self, ip2whois_client):
        assert ip2whois_client.api_key == "dummykey"

    @patch.object(requests.Session, "get")
    def test_get_whois(self, mock_requests_get, test_data, ip2whois_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json.loads(test_data("ip2whois_whois_hotmail.json"))
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
