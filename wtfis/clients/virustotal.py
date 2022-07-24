import json
import requests

from requests.exceptions import HTTPError, JSONDecodeError
# from pydantic import ValidationError
from typing import Optional

from wtfis.models.virustotal import Domain


class VTClient:
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

    def _get(self, request: str) -> Optional[dict]:
        try:
            resp = self.s.get(self.baseurl + request)
            resp.raise_for_status()

            return json.loads(json.dumps((resp.json())))["data"]["attributes"]
        except (HTTPError, JSONDecodeError):
            raise

    def get_domain(self, domain: str) -> Domain:
        return Domain.parse_obj(self._get(f"/domains/{domain}"))
