from typing import Optional

from requests.exceptions import HTTPError

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.greynoise import GreynoiseIp, GreynoiseIpMap


class GreynoiseClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    Greynoise client
    """

    baseurl = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "Greynoise"

    def _get_ip(self, ip: str) -> Optional[GreynoiseIp]:
        # Let a 404 or invalid IP pass
        try:
            return GreynoiseIp.model_validate(
                self._get(f"/{ip}", headers={"key": self.api_key})
            )
        except HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def enrich_ips(self, *ips: str) -> GreynoiseIpMap:
        greynoise_map = {}
        for ip in ips:
            ip_data = self._get_ip(ip)
            if ip_data:
                greynoise_map[ip_data.ip] = ip_data
        return GreynoiseIpMap.model_validate(greynoise_map)
