from typing import Optional

from shodan import Shodan

from wtfis.clients.base import BaseClient, BaseIpEnricherClient
from wtfis.models.shodan import ShodanIp, ShodanIpMap


class ShodanClient(BaseClient, BaseIpEnricherClient):
    """
    Shodan client
    """

    def __init__(self, api_key: str) -> None:
        self.s = Shodan(api_key)

    @property
    def name(self) -> str:
        return "Shodan"

    def _get_ip(self, ip: str) -> Optional[ShodanIp]:
        return ShodanIp.model_validate(self.s.host(ip, minify=False))

    def enrich_ips(self, *ips: str) -> ShodanIpMap:
        shodan_map = {}
        for ip in ips:
            ip_data = self._get_ip(ip)
            if ip_data:
                shodan_map[ip_data.ip_str] = ip_data
        return ShodanIpMap.model_validate(shodan_map)
