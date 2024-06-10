import abc
import json
from typing import Optional, Union

import requests

from wtfis.models.base import WhoisBase
from wtfis.models.types import DomainEnrichmentType, IpEnrichmentType


class AbstractAttribute:
    def __get__(self, obj, type):  # pragma: no coverage
        raise NotImplementedError("This attribute must be set")


class BaseClient(abc.ABC):
    """
    Base client
    All clients should at least inherit from this class
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:  # pragma: no coverage
        return NotImplemented


class BaseRequestsClient(BaseClient):
    """
    Client that uses the requests library
    """

    baseurl: Union[AbstractAttribute, str] = AbstractAttribute()

    def __init__(self) -> None:
        self.s = requests.Session()

    def _get(
        self,
        request: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        resp = self.s.get(self.baseurl + request, params=params, headers=headers)
        resp.raise_for_status()

        return json.loads(json.dumps((resp.json())))

    def _post(
        self,
        request: str,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        resp = self.s.post(self.baseurl + request, data=data, headers=headers)
        resp.raise_for_status()

        return json.loads(json.dumps((resp.json())))


class BaseWhoisClient(abc.ABC):
    """
    Client used for whois lookups
    """

    @abc.abstractmethod
    def get_whois(self, entity: str) -> WhoisBase:  # pragma: no coverage
        return NotImplemented


class BaseDomainEnricherClient(abc.ABC):
    """
    Client used for domain/FQDN enrichments
    """

    @abc.abstractmethod
    def enrich_domains(
        self, *domains: str
    ) -> DomainEnrichmentType:  # pragma: no coverage
        return NotImplemented


class BaseIpEnricherClient(abc.ABC):
    """
    Client used for IP enrichments
    """

    @abc.abstractmethod
    def enrich_ips(self, *ips: str) -> IpEnrichmentType:  # pragma: no coverage
        return NotImplemented
