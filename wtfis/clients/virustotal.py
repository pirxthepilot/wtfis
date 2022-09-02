from typing import Optional

from wtfis.clients.base import BaseClient
from wtfis.models.virustotal import (
    Domain,
    IpAddress,
    HistoricalWhois,
    Resolutions,
)
from wtfis.utils import is_ip


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

    def get_ip_address(self, ip: str) -> IpAddress:
        return IpAddress.parse_obj(self._get(f"/ip_addresses/{ip}"))

    def get_ip_whois(self, ip: str) -> HistoricalWhois:
        return HistoricalWhois.parse_obj(self._get(f"/ip_addresses/{ip}/historical_whois"))

    def get_whois(self, entity: str) -> HistoricalWhois:
        """ Generalized for domain and IP """
        if is_ip(entity):
            return self.get_ip_whois(entity)
        else:
            return self.get_domain_whois(entity)
