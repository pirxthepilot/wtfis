"""
Logic handler for domain and hostname inputs
"""
from rich.console import Console
from rich.progress import Progress
from typing import Optional, Union

from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.common import WhoisType
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.virustotal import Domain, Resolutions


class DomainHandler:
    def __init__(
        self,
        domain: str,
        vt_client: VTClient,
        ip_enricher_client: Union[IpWhoisClient, ShodanClient],
        whois_client: Union[Ip2WhoisClient, PTClient, VTClient],
        console: Console,
        progress: Progress,
        max_resolutions: int = 0,
    ):
        self.entity = domain
        self.console = console
        self.progress = progress
        self.max_resolutions = max_resolutions
        self.warnings = []

        self._vt = vt_client
        self._enricher = ip_enricher_client
        self._whois = whois_client

        self.vt_info: Optional[Domain] = None
        self.resolutions: Optional[Resolutions] = None
        self.ip_enrich: Union[IpWhoisMap, ShodanIpMap, None] = None
        self.whois: Optional[WhoisType] = None

    def _fetch_vt_domain(self) -> None:
        self.vt_info = self._vt.get_domain(self.entity)

    def _fetch_vt_resolutions(self) -> None:
        self.resolutions = self._vt.get_domain_resolutions(self.entity)

    def _fetch_ip_enrichments(self) -> None:
        self.ip_enrich = self._enricher.bulk_get_ip(self.resolutions, self.max_resolutions)

    def _fetch_whois(self) -> None:
        self.whois = self._whois.get_whois(self.entity)

    def fetch_data(self):
        task1 = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task1, advance=33)
        self._fetch_vt_domain()
        if self.max_resolutions != 0:
            self.progress.update(task1, advance=33)
            self._fetch_vt_resolutions()
        self.progress.update(task1, completed=100)

        if self.max_resolutions != 0:
            task2 = self.progress.add_task(f"Fetching IP enrichments from {self._enricher.name}")
            self.progress.update(task2, advance=50)
            self._fetch_ip_enrichments()
            self.progress.update(task2, advance=50)

        task3 = self.progress.add_task(f"Fetching domain whois from {self._whois.name}")
        self.progress.update(task3, advance=50)
        self._fetch_whois()
        self.progress.update(task3, completed=100)
