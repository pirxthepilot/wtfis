from shodan import Shodan
from shodan.exception import APIError
from typing import Optional

from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.virustotal import Resolutions


class ShodanClient:
    """
    Shodan client
    """
    def __init__(self, api_key: str) -> None:
        self.s = Shodan(api_key)

    @property
    def name(self) -> str:
        return "Shodan"

    def get_ip(self, ip: str) -> Optional[ShodanIp]:
        try:
            return ShodanIp.model_validate(self.s.host(ip, minify=False))
        except APIError as e:
            if str(e) == "Invalid API key":
                raise APIError("Invalid Shodan API key")
            else:
                return None

    def bulk_get_ip(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> ShodanIpMap:
        shodan_map = {}
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            ip_data = self.get_ip(ip.attributes.ip_address)
            if ip_data:
                shodan_map[ip_data.ip_str] = ip_data
        return ShodanIpMap.model_validate(shodan_map)

    def single_get_ip(self, ip: str) -> ShodanIpMap:
        shodan_map = {}
        ip_data = self.get_ip(ip)
        if ip_data:
            shodan_map[ip] = ip_data
        return ShodanIpMap.model_validate(shodan_map)
