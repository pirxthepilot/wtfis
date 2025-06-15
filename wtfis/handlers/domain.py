"""
Logic handler for domain and hostname inputs
"""

from dataclasses import dataclass
from typing import Optional

from requests.exceptions import HTTPError

from wtfis.handlers.base import (
    BaseHandler,
    common_exception_handler,
    failopen_exception_handler,
)
from wtfis.models.virustotal import Resolutions


@dataclass
class DomainHandler(BaseHandler):
    max_resolutions: int = 0

    def __post_init__(self):
        super().__post_init__()

        # Extended attributes
        self.resolutions: Optional[Resolutions] = None

    @common_exception_handler
    def _fetch_vt_domain(self) -> None:
        self.vt_info = self._vt.get_domain(self.entity)

    @common_exception_handler
    def _fetch_vt_resolutions(self) -> None:
        # Let continue if rate limited
        try:
            self.resolutions = self._vt.get_domain_resolutions(self.entity)
        except HTTPError as e:
            if e.response.status_code == 429:
                self.warnings.append(f"Could not fetch Virustotal resolutions: {e}")
            else:
                raise

    @common_exception_handler
    @failopen_exception_handler("_urlhaus")
    def _fetch_urlhaus(self) -> None:
        if self._urlhaus:
            self.urlhaus = self._urlhaus.enrich_domains(self.entity)

    def fetch_data(self):
        yield "Fetching data from Virustotal", 33
        self._fetch_vt_domain()
        if self.max_resolutions != 0:
            yield 33
            self._fetch_vt_resolutions()

        if self.resolutions and self.resolutions.data:
            yield f"Fetching IP location and ASN from {self._geoasn.name}", 50
            self._fetch_geoasn(*self.resolutions.ip_list(self.max_resolutions))

            if self._shodan:
                yield f"Fetching IP data from {self._shodan.name}", 50
                self._fetch_shodan(*self.resolutions.ip_list(self.max_resolutions))

            if self._greynoise:
                yield f"Fetching IP data from {self._greynoise.name}", 50
                self._fetch_greynoise(*self.resolutions.ip_list(self.max_resolutions))

            if self._abuseipdb:
                yield f"Fetching IP data from {self._abuseipdb.name}", 50
                self._fetch_abuseipdb(*self.resolutions.ip_list(self.max_resolutions))

        if self._urlhaus:
            yield f"Fetching domain data from {self._urlhaus.name}", 50
            self._fetch_urlhaus()

        yield f"Fetching domain whois from {self._whois.name}", 50
        self._fetch_whois()
