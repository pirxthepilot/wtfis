from wtfis.clients.base import BaseClient
from wtfis.models.whoisjson import Whois
from wtfis.utils import refang


class WhoisJsonClient(BaseClient):
    """
    WhoisJSON client
    """
    baseurl = "https://whoisjson.com/api/v1"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.s.headers.update({
            "Authorization": f"TOKEN={api_key}",
        })

    def get_whois(self, domain: str) -> Whois:
        params = {"domain": refang(domain)}
        return Whois.parse_obj(self._get("/whois", params))
