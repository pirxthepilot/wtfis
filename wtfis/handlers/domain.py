"""
Logic handler for domain and hostname inputs
"""
from requests.exceptions import HTTPError, RequestException
from rich.console import Console
from rich.progress import Progress
from shodan.exception import APIError
from typing import Optional, Union

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.handlers.base import BaseHandler, common_exception_handler
from wtfis.models.virustotal import Resolutions


class DomainHandler(BaseHandler):
    def __init__(
        self,
        entity: str,
        console: Console,
        progress: Progress,
        vt_client: VTClient,
        ip_enricher_client: Union[IpWhoisClient, ShodanClient],
        whois_client: Union[Ip2WhoisClient, PTClient, VTClient],
        greynoise_client: Optional[GreynoiseClient],
        max_resolutions: int = 0,
    ):
        super().__init__(entity, console, progress, vt_client, ip_enricher_client,
                         whois_client, greynoise_client)

        # Extended attributes
        self.max_resolutions = max_resolutions
        self.resolutions: Resolutions = None  # type: ignore

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
    def _fetch_ip_enrichments(self) -> None:
        # Let continue on any error
        try:
            self.ip_enrich = self._enricher.bulk_get_ip(self.resolutions, self.max_resolutions)
        except (APIError, RequestException) as e:  # Covers both ipwhois and Shodan exceptions
            # With warning message
            self.warnings.append(f"Could not fetch {self._enricher.name}: {e}")

    @common_exception_handler
    def _fetch_greynoise(self) -> None:
        # Let continue on any error
        try:
            if self._greynoise:
                self.greynoise = self._greynoise.bulk_get_ip(self.resolutions, self.max_resolutions)
        except RequestException as e:  # All other errors
            # With warning message
            self.warnings.append(f"Could not fetch Greynoise: {e}")

    def fetch_data(self):
        task_v = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task_v, advance=33)
        self._fetch_vt_domain()
        if self.max_resolutions != 0:
            self.progress.update(task_v, advance=33)
            self._fetch_vt_resolutions()
        self.progress.update(task_v, completed=100)

        if self.resolutions and self.resolutions.data:
            task_r = self.progress.add_task(f"Fetching IP enrichments from {self._enricher.name}")
            self.progress.update(task_r, advance=50)
            self._fetch_ip_enrichments()
            self.progress.update(task_r, completed=100)

        if self._greynoise:
            task_g = self.progress.add_task(f"Fetching IP enrichments from {self._greynoise.name}")
            self.progress.update(task_g, advance=50)
            self._fetch_greynoise()
            self.progress.update(task_g, completed=100)

        task_w = self.progress.add_task(f"Fetching domain whois from {self._whois.name}")
        self.progress.update(task_w, advance=50)
        self._fetch_whois()
        self.progress.update(task_w, completed=100)
