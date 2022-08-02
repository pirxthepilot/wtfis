import json

from requests.exceptions import HTTPError, JSONDecodeError
from typing import Optional


class BaseClient:
    """
    Base client
    """
    def _get(self, request: str, params: Optional[dict] = None) -> Optional[dict]:
        try:
            resp = self.s.get(self.baseurl + request, params=params)
            resp.raise_for_status()

            return json.loads(json.dumps((resp.json())))
        except (HTTPError, JSONDecodeError):
            raise
