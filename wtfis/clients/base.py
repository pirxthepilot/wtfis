import abc
import json
import requests

from typing import Optional, Union


class AbstractAttribute:
    def __get__(self, obj, type):  # pragma: no coverage
        raise NotImplementedError("This attribute must be set")


class BaseClient(abc.ABC):
    """
    Base client
    """
    baseurl: Union[AbstractAttribute, str] = AbstractAttribute()

    def __init__(self) -> None:
        self.s = requests.Session()

    @property
    @abc.abstractmethod
    def name(self) -> str:  # pragma: no coverage
        return NotImplemented

    def _get(
        self,
        request: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        resp = self.s.get(self.baseurl + request, params=params, headers=headers)
        resp.raise_for_status()

        return json.loads(json.dumps((resp.json())))
