from typing import Optional

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.ipwhois import IpWhois, IpWhoisMap


class IpWhoisClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    IPWhois client
    """

    baseurl = "https://ipwho.is"

    @property
    def name(self) -> str:
        return "IPWhois"

    def _get_ipwhois(self, ip: str) -> Optional[IpWhois]:
        result = self._get(f"/{ip}")
        return IpWhois.model_validate(result) if result.get("success") is True else None

    def enrich_ips(self, *ips: str) -> IpWhoisMap:
        map_ = {}
        for ip in ips:
            ipwhois = self._get_ipwhois(ip)
            if ipwhois:
                map_[ipwhois.ip] = ipwhois
        return IpWhoisMap.model_validate(map_)
