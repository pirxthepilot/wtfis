from typing import Optional

from requests.exceptions import HTTPError

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.abuseipdb import abuseIPDBIp, abuseIPDBIpMap


class abuseIPDBClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    abuseIPDB client
    """
    baseurl = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "abuseIPDB"

    def _get_ip(self, ip: str) -> Optional[abuseIPDBIp]:
        # Let a 404 or invalid IP pass
        try:
            params = {"ipAddress": ip, 'maxAgeInDays': '90'}
            headers = {"key": self.api_key, 'Accept': 'application/json'}

            response = self._get(request="", headers=headers, params=params)

            return abuseIPDBIp.model_validate(response["data"])
        except HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def enrich_ips(self, *ips: str) -> abuseIPDBIpMap:
        abuseIPDB_map = {}
        for ip in ips:
            ip_data = self._get_ip(ip)
            if ip_data:
                abuseIPDB_map[ip_data.ipAddress] = ip_data
        return abuseIPDBIpMap.model_validate(abuseIPDB_map)
