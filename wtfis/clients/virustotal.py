import requests

from wtfis.clients.base import BaseClient
from wtfis.models.virustotal import Domain, Resolutions


class VTClient(BaseClient):
    """
    Virustotal client
    """
    baseurl = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self.s = requests.Session()
        self.s.headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

    def get_domain(self, domain: str) -> Domain:
        return Domain.parse_obj(self._get(f"/domains/{domain}"))

    def get_domain_resolutions(self, domain: str) -> Resolutions:
        return Resolutions.parse_obj(self._get(f"/domains/{domain}/resolutions"))

    def get_domain_whois(self, domain: str) -> dict:
        return self._get(f"/domains/{domain}/historical_whois")
