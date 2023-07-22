from requests.exceptions import HTTPError

from wtfis.clients.base import BaseClient
from wtfis.models.ip2whois import Whois
from wtfis.utils import refang


class Ip2WhoisClient(BaseClient):
    """
    IP2WHOIS client
    """
    baseurl = "https://api.ip2whois.com/v2"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "IP2Whois"

    def get_whois(self, domain: str) -> Whois:
        params = {
            "key": self.api_key,
            "domain": refang(domain),
        }

        # Let a 404 or invalid domain pass
        try:
            return Whois.model_validate(self._get("/", params))
        except HTTPError as e:
            if (
                e.response.status_code == 404 or
                (e.response.status_code == 400 and
                 e.response.json().get("error", {})["error_code"] == 10007)
            ):
                return Whois.model_validate({})
            raise
