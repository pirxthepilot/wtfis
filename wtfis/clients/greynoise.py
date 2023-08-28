from requests.exceptions import HTTPError
from typing import Optional

from wtfis.clients.base import BaseClient
from wtfis.models.greynoise import GreynoiseIp, GreynoiseIpMap
from wtfis.models.virustotal import Resolutions


class GreynoiseClient(BaseClient):
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

    def get_ip(self, ip: str) -> Optional[GreynoiseIp]:
        # Let a 404 or invalid IP pass
        try:
            return GreynoiseIp.model_validate(
                self._get(f"/{ip}", headers={"key": self.api_key})
            )
        except HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def bulk_get_ip(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> GreynoiseIpMap:
        greynoise_map = {}
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            ip_data = self.get_ip(ip.attributes.ip_address)
            if ip_data:
                greynoise_map[ip_data.ip] = ip_data
        return GreynoiseIpMap.model_validate(greynoise_map)

    def single_get_ip(self, ip: str) -> GreynoiseIpMap:
        greynoise_map = {}
        ip_data = self.get_ip(ip)
        if ip_data:
            greynoise_map[ip] = ip_data
        return GreynoiseIpMap.model_validate(greynoise_map)
