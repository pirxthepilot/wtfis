import requests

from wtfis.clients.base import BaseClient
from wtfis.models.ipwhois import IpWhois
from wtfis.models.virustotal import Resolutions

from typing import List, Optional


class IpWhoisClient(BaseClient):
    """
    IPWhois client
    """
    baseurl = "https://ipwho.is"

    def __init__(self) -> None:
        self.s = requests.Session()

    def get_ipwhois(self, ip: str) -> Optional[IpWhois]:
        return IpWhois.parse_obj(self._get(f"/{ip}"))

    def bulk_get_ipwhois(
        self,
        resolutions: Resolutions,
        max_ips_to_enrich: int
    ) -> Optional[List[IpWhois]]:
        results = []
        for idx, ip in enumerate(resolutions.data):
            if idx == max_ips_to_enrich:
                break
            ipwhois = self.get_ipwhois(ip.attributes.ip_address)
            if ipwhois:
                results.append(ipwhois)
        return results if results else None
