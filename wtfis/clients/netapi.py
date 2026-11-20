from wtfis.clients.base import (
    BaseDomainEnricherClient,
    BaseIpEnricherClient,
    BaseRequestsClient,
)
from wtfis.models.netapi import NetApi, NetApiMap


class NetApiClient(BaseRequestsClient, BaseDomainEnricherClient, BaseIpEnricherClient):
    """
    NetAPI client
    """

    baseurl = "https://netapi.com/api-json"

    @property
    def name(self) -> str:
        return "NetAPI"

    def _check(self, value: str) -> NetApi:
        params = {"method": "compromised-check", "value": value}
        return NetApi.model_validate(self._get("/", params=params))

    def _enrich(self, *entities: str) -> NetApiMap:
        """Method is the same whether input is a domain or IP"""
        netapi_map = {}
        for entity in entities:
            netapi_map[entity] = self._check(entity)
        return NetApiMap.model_validate(netapi_map)

    def enrich_domains(self, *domains: str) -> NetApiMap:
        return self._enrich(*domains)

    def enrich_ips(self, *ips: str) -> NetApiMap:
        return self._enrich(*ips)
