from typing import Optional

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.ip2location import Ip2Location, Ip2LocationMap


class Ip2LocationClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    IP2Location client
    """

    baseurl = "https://api.ip2location.io"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "IP2Location"

    def _get_ip2location(self, ip: str) -> Optional[Ip2Location]:
        params = {
            "key": self.api_key,
            "ip": ip,
            "format": "json",
        }
        return Ip2Location.model_validate(self._get("/", params=params))

    def enrich_ips(self, *ips: str) -> Ip2LocationMap:
        map_ = {}
        for ip in ips:
            ip2location = self._get_ip2location(ip)
            if ip2location:
                map_[ip2location.ip] = ip2location
        return Ip2LocationMap.model_validate(map_)
