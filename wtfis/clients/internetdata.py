from typing import Optional

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.internetdata import InternetData, InternetDataMap


class InternetDataClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    InternetData client
    """

    baseurl = "https://api.internetdata.io"

    @property
    def name(self) -> str:
        return "InternetData"

    def _get_internetdata(self, ip: str) -> Optional[InternetData]:
        result = self._get(f"/{ip}")
        return InternetData.model_validate(result) if result else None

    def enrich_ips(self, *ips: str) -> InternetDataMap:
        map_ = {}
        for ip in ips:
            internetdata = self._get_internetdata(ip)
            if internetdata:
                map_[internetdata.ip] = internetdata
        return InternetDataMap.model_validate(map_)
