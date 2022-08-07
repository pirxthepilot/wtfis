import json
import requests

from typing import Optional, Union


class AbstractAttribute:
    def __get__(self, obj, type):
        raise NotImplementedError("This attribute must be set")


class BaseClient:
    """
    Base client
    """
    baseurl: Union[AbstractAttribute, str] = AbstractAttribute()

    def __init__(self) -> None:
        self.s = requests.Session()

    def _get(self, request: str, params: Optional[dict] = None) -> dict:
        resp = self.s.get(self.baseurl + request, params=params)
        resp.raise_for_status()

        return json.loads(json.dumps((resp.json())))
