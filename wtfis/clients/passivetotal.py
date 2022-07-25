import json
import requests

from requests.exceptions import HTTPError, JSONDecodeError
# from pydantic import ValidationError
from typing import Optional

from wtfis.models.passivetotal import Whois


class PTClient:
    """
    Passivetotal client
    """
    baseurl = "https://api.riskiq.net/pt/v2"

    def __init__(self, api_user: str, api_key: str) -> None:
        self.s = requests.Session()
        self.s.auth = (api_user, api_key)

    def _get(self, request: str, params: Optional[dict] = None) -> Optional[dict]:
        try:
            resp = self.s.get(self.baseurl + request, params=params)
            resp.raise_for_status()

            return json.loads(json.dumps((resp.json())))
        except (HTTPError, JSONDecodeError):
            raise

    def _query(self, path: str, query: str) -> Optional[dict]:
        return self._get(
            path,
            params={"query": query}
        )

    def get_passive_dns(self, domain: str) -> dict:
        return self._query("/dns/passive", domain)

    def get_whois(self, domain: str) -> Optional[Whois]:
        return Whois.parse_obj(self._query("/whois", domain))
