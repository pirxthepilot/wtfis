from wtfis.clients.base import BaseClient
from wtfis.models.passivetotal import Whois
from wtfis.utils import refang


class PTClient(BaseClient):
    """
    Passivetotal client
    """
    baseurl = "https://api.riskiq.net/pt/v2"

    def __init__(self, api_user: str, api_key: str) -> None:
        super().__init__()
        self.s.auth = (api_user, api_key)

    @property
    def name(self) -> str:
        return "Passivetotal"

    def _query(self, path: str, query: str) -> dict:
        return self._get(
            path,
            params={"query": query}
        )

    def get_passive_dns(self, domain: str) -> dict:
        return self._query("/dns/passive", refang(domain))

    def get_whois(self, entity: str) -> Whois:
        return Whois.model_validate(self._query("/whois", refang(entity)))
