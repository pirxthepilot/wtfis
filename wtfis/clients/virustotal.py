from typing import Optional

from wtfis.clients.base import BaseClient
from wtfis.models.virustotal import Domain, HistoricalWhois, Resolutions


class VTClient(BaseClient):
    """
    Virustotal client
    """
    baseurl = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.s.headers.update({
            "x-apikey": api_key,
            "Accept": "application/json",
        })

    def get_domain(self, domain: str) -> Domain:
        return Domain.parse_obj(self._get(f"/domains/{domain}"))

    def get_domain_resolutions(self, domain: str) -> Optional[Resolutions]:
        return Resolutions.parse_obj(self._get(f"/domains/{domain}/resolutions"))

    def get_domain_whois(self, domain: str) -> HistoricalWhois:
        return HistoricalWhois.parse_obj(self._get(f"/domains/{domain}/historical_whois"))
