from wtfis.clients.base import BaseClient
from wtfis.models.ipwhois import IpWhois
from wtfis.models.virustotal import Resolutions

from typing import List, Optional


class IpWhoisClient(BaseClient):
    """
    IPWhois client
    """
    baseurl = "https://ipwho.is"

    def get_ipwhois(self, ip: str) -> Optional[IpWhois]:
        result = self._get(f"/{ip}")
        return IpWhois.parse_obj(result) if result.get("success") is True else None

    def bulk_get_ipwhois(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> List[IpWhois]:
        results = []
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            ipwhois = self.get_ipwhois(ip.attributes.ip_address)
            if ipwhois:
                results.append(ipwhois)
        return results
