from shodan import Shodan
from shodan.exception import APIError

from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.virustotal import Resolutions


class ShodanClient:
    """
    Shodan client
    """
    def __init__(self, api_key: str) -> None:
        self.s = Shodan(api_key)

    def get_ip(self, ip: str) -> ShodanIp:
        return ShodanIp.parse_obj(self.s.host(ip, minify=False))

    def bulk_get_ip(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> ShodanIpMap:
        shodan_map = {}
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            try:
                ip_data = self.get_ip(ip.attributes.ip_address)
            except APIError as e:
                if str(e) == "Invalid API key":
                    raise APIError("Invalid Shodan API key")
                else:
                    ip_data = None
            if ip_data:
                shodan_map[ip_data.ip_str] = ip_data
        return ShodanIpMap(__root__=shodan_map)
