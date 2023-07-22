from wtfis.clients.base import BaseClient
from wtfis.models.virustotal import (
    Domain,
    IpAddress,
    Resolutions,
    Whois,
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

    @property
    def name(self) -> str:
        return "Virustotal"

    def get_domain(self, domain: str) -> Domain:
        return Domain.model_validate(self._get(f"/domains/{domain}"))

    def get_domain_resolutions(self, domain: str) -> Resolutions:
        return Resolutions.model_validate(self._get(f"/domains/{domain}/resolutions"))

    def get_domain_whois(self, domain: str) -> Whois:
        return Whois.model_validate(self._get(f"/domains/{domain}/historical_whois"))

    def get_ip_address(self, ip: str) -> IpAddress:
        return IpAddress.model_validate(self._get(f"/ip_addresses/{ip}"))

    def get_ip_whois(self, ip: str) -> Whois:
        return Whois.model_validate(self._get(f"/ip_addresses/{ip}/historical_whois"))

    def get_whois(self, entity: str) -> Whois:
        """ Generalized for domain and IP """
        if is_ip(entity):
            return self.get_ip_whois(entity)
        else:
            return self.get_domain_whois(entity)
