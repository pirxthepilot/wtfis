from typing import Optional

from requests.exceptions import HTTPError

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.shodan import ShodanIp, ShodanIpMap


class ShodanClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    Shodan client
    """

    baseurl = "https://api.shodan.io/shodan"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "Shodan"

    def _get_ip(self, ip: str) -> Optional[ShodanIp]:
        params = {"key": self.api_key}
        try:
            return ShodanIp.model_validate(self._get(f"/host/{ip}", params=params))
        except HTTPError as e:
            # 404 means the IP is invalid or not in Shodan; we don't want to raise an error
            if e.response.status_code == 404:
                return None
            raise e

    def enrich_ips(self, *ips: str) -> ShodanIpMap:
        shodan_map = {}
        for ip in ips:
            ip_data = self._get_ip(ip)
            if ip_data:
                shodan_map[ip_data.ip_str] = ip_data
        return ShodanIpMap.model_validate(shodan_map)
