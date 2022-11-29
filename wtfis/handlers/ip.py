"""
Logic handler for IP address inputs
"""
from wtfis.handlers.base import BaseHandler, common_exception_handler


class IpAddressHandler(BaseHandler):
    @common_exception_handler
    def _fetch_vt_ip_address(self) -> None:
        self.vt_info = self._vt.get_ip_address(self.entity)

    @common_exception_handler
    def _fetch_ip_enrichments(self) -> None:
        self.ip_enrich = self._enricher.single_get_ip(self.entity)

    def fetch_data(self):
        task1 = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task1, advance=50)
        self._fetch_vt_ip_address()
        self.progress.update(task1, completed=100)

        task2 = self.progress.add_task(f"Fetching IP enrichments from {self._enricher.name}")
        self.progress.update(task2, advance=50)
        self._fetch_ip_enrichments()
        self.progress.update(task2, completed=100)

        task3 = self.progress.add_task(f"Fetching IP whois from {self._whois.name}")
        self.progress.update(task3, advance=50)
        self._fetch_whois()
        self.progress.update(task3, completed=100)
