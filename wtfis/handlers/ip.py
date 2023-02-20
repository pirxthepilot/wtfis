"""
Logic handler for IP address inputs
"""
from requests.exceptions import HTTPError

from wtfis.handlers.base import BaseHandler, common_exception_handler
from wtfis.models.greynoise import GreynoiseIpMap


class IpAddressHandler(BaseHandler):
    @common_exception_handler
    def _fetch_vt_ip_address(self) -> None:
        self.vt_info = self._vt.get_ip_address(self.entity)

    @common_exception_handler
    def _fetch_ip_enrichments(self) -> None:
        self.ip_enrich = self._enricher.single_get_ip(self.entity)

    @common_exception_handler
    def _fetch_greynoise(self) -> None:
        # Let continue on certain HTTP errors
        try:
            if self._greynoise:
                self.greynoise = self._greynoise.single_get_ip(self.entity)
        except HTTPError as e:
            # With warning message
            if e.response.status_code in (400, 429, 500):
                self.greynoise = GreynoiseIpMap.empty()
                self.warnings.append(f"Could not fetch Greynoise: {e}")
            # No warning message
            elif e.response.status_code == 404:
                self.greynoise = GreynoiseIpMap.empty()
            else:
                raise

    def fetch_data(self):
        task1 = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task1, advance=50)
        self._fetch_vt_ip_address()
        self.progress.update(task1, completed=100)

        task2 = self.progress.add_task(f"Fetching IP enrichments from {self._enricher.name}")
        self.progress.update(task2, advance=50)
        self._fetch_ip_enrichments()
        self.progress.update(task2, completed=100)

        if self._greynoise:
            task3 = self.progress.add_task(f"Fetching IP enrichments from {self._greynoise.name}")
            self.progress.update(task3, advance=50)
            self._fetch_greynoise()
            self.progress.update(task3, completed=100)

        task4 = self.progress.add_task(f"Fetching IP whois from {self._whois.name}")
        self.progress.update(task4, advance=50)
        self._fetch_whois()
        self.progress.update(task4, completed=100)
