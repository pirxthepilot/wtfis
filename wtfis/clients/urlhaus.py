from wtfis.clients.base import (
    BaseDomainEnricherClient,
    BaseIpEnricherClient,
    BaseRequestsClient,
)
from wtfis.models.urlhaus import UrlHaus, UrlHausMap


class UrlHausClient(BaseRequestsClient, BaseDomainEnricherClient, BaseIpEnricherClient):
    """
    URLhaus client
    """
    baseurl = "https://urlhaus-api.abuse.ch/v1"

    @property
    def name(self) -> str:
        return "URLhaus"

    def _get_host(self, host: str) -> UrlHaus:
        return UrlHaus.model_validate(self._post("/host", {"host": host}))

    def _enrich_domains_or_ips(self, *entities: str) -> UrlHausMap:
        """ Method is the same whether input is a domain or IP """
        urlhaus_map = {}
        for entity in entities:
            data = self._get_host(entity)
            if data.host:
                urlhaus_map[data.host] = data
        return UrlHausMap.model_validate(urlhaus_map)

    def enrich_domains(self, *domains: str) -> UrlHausMap:
        return self._enrich_domains_or_ips(*domains)

    def enrich_ips(self, *ips: str) -> UrlHausMap:
        return self._enrich_domains_or_ips(*ips)
