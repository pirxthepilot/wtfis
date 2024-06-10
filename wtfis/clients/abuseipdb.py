from typing import Optional

from wtfis.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.models.abuseipdb import AbuseIpDb, AbuseIpDbMap


class AbuseIpDbClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    AbuseIPDB client
    """

    baseurl = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def _get_ip(self, ip: str) -> Optional[AbuseIpDb]:
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"key": self.api_key, "Accept": "application/json"}

        response = self._get(request="/check", headers=headers, params=params)

        return AbuseIpDb.model_validate(response["data"])

    def enrich_ips(self, *ips: str) -> AbuseIpDbMap:
        abuseipdb_map = {}
        for ip in ips:
            ip_data = self._get_ip(ip)
            if ip_data:
                abuseipdb_map[ip_data.ip_address] = ip_data
        return AbuseIpDbMap.model_validate(abuseipdb_map)
