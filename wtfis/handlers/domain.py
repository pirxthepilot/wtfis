"""
Logic handler for domain and hostname inputs
"""

from typing import Optional

from requests.exceptions import HTTPError
from rich.console import Console
from rich.progress import Progress

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.types import IpGeoAsnClientType, IpWhoisClientType
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.handlers.base import (
    BaseHandler,
    common_exception_handler,
    failopen_exception_handler,
)
from wtfis.models.virustotal import Resolutions


class DomainHandler(BaseHandler):
    def __init__(
        self,
        entity: str,
        console: Console,
        progress: Progress,
        vt_client: VTClient,
        ip_geoasn_client: IpGeoAsnClientType,
        whois_client: IpWhoisClientType,
        shodan_client: Optional[ShodanClient],
        greynoise_client: Optional[GreynoiseClient],
        abuseipdb_client: Optional[AbuseIpDbClient],
        urlhaus_client: Optional[UrlHausClient],
        max_resolutions: int = 0,
    ):
        super().__init__(
            entity,
            console,
            progress,
            vt_client,
            ip_geoasn_client,
            whois_client,
            shodan_client,
            greynoise_client,
            abuseipdb_client,
            urlhaus_client,
        )

        # Extended attributes
        self.max_resolutions = max_resolutions
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
        task_v = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task_v, advance=33)
        self._fetch_vt_domain()
        if self.max_resolutions != 0:
            self.progress.update(task_v, advance=33)
            self._fetch_vt_resolutions()
        self.progress.update(task_v, completed=100)

        if self.resolutions and self.resolutions.data:
            task_g = self.progress.add_task(
                f"Fetching IP location and ASN from {self._geoasn.name}"
            )
            self.progress.update(task_g, advance=50)
            self._fetch_geoasn(*self.resolutions.ip_list(self.max_resolutions))
            self.progress.update(task_g, completed=100)

            if self._shodan:
                task_s = self.progress.add_task(
                    f"Fetching IP data from {self._shodan.name}"
                )
                self.progress.update(task_s, advance=50)
                self._fetch_shodan(*self.resolutions.ip_list(self.max_resolutions))
                self.progress.update(task_s, completed=100)

            if self._greynoise:
                task_g = self.progress.add_task(
                    f"Fetching IP data from {self._greynoise.name}"
                )
                self.progress.update(task_g, advance=50)
                self._fetch_greynoise(*self.resolutions.ip_list(self.max_resolutions))
                self.progress.update(task_g, completed=100)

            if self._abuseipdb:
                task_g = self.progress.add_task(
                    f"Fetching IP data from {self._abuseipdb.name}"
                )
                self.progress.update(task_g, advance=50)
                self._fetch_abuseipdb(*self.resolutions.ip_list(self.max_resolutions))
                self.progress.update(task_g, completed=100)

        if self._urlhaus:
            task_u = self.progress.add_task(
                f"Fetching domain data from {self._urlhaus.name}"
            )
            self.progress.update(task_u, advance=50)
            self._fetch_urlhaus()
            self.progress.update(task_u, completed=100)

        task_w = self.progress.add_task(
            f"Fetching domain whois from {self._whois.name}"
        )
        self.progress.update(task_w, advance=50)
        self._fetch_whois()
        self.progress.update(task_w, completed=100)
