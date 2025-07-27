from typing import Optional

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.ipinfo import IpInfo, IpInfoMap


class IpInfoClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    IPinfo client
    """

    baseurl = "https://ipinfo.io"

    @property
    def name(self) -> str:
        return "IPinfo"

    def _get_ipinfo(self, ip: str) -> Optional[IpInfo]:
        result = self._get(f"/{ip}/json")
        return IpInfo.model_validate(result) if result else None

    def enrich_ips(self, *ips: str) -> IpInfoMap:
        map_ = {}
        for ip in ips:
            ipinfo = self._get_ipinfo(ip)
            if ipinfo:
                map_[ipinfo.ip] = ipinfo
        return IpInfoMap.model_validate(map_)
