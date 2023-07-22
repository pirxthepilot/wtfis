from wtfis.clients.base import BaseClient
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.virustotal import Resolutions

from typing import Optional


class IpWhoisClient(BaseClient):
    """
    IPWhois client
    """
    baseurl = "https://ipwho.is"

    def get_ipwhois(self, ip: str) -> Optional[IpWhois]:
        result = self._get(f"/{ip}")
        return IpWhois.model_validate(result) if result.get("success") is True else None

    @property
    def name(self) -> str:
        return "IPWhois"

    def bulk_get_ip(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> IpWhoisMap:
        ipwhois_map = {}
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            ipwhois = self.get_ipwhois(ip.attributes.ip_address)
            if ipwhois:
                ipwhois_map[ipwhois.ip] = ipwhois
        return IpWhoisMap.model_validate(ipwhois_map)

    def single_get_ip(self, ip: str) -> IpWhoisMap:
        ipwhois_map = {}
        ipwhois = self.get_ipwhois(ip)
        if ipwhois:
            ipwhois_map[ip] = ipwhois
        return IpWhoisMap.model_validate(ipwhois_map)
