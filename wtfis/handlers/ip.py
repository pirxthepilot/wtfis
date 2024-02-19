"""
Logic handler for IP address inputs
"""
from wtfis.handlers.base import (
    BaseHandler,
    common_exception_handler,
    failopen_exception_handler,
)


class IpAddressHandler(BaseHandler):
    @common_exception_handler
    def _fetch_vt_ip_address(self) -> None:
        self.vt_info = self._vt.get_ip_address(self.entity)

    @common_exception_handler
    @failopen_exception_handler("_urlhaus")
    def _fetch_urlhaus(self) -> None:
        if self._urlhaus:
            self.urlhaus = self._urlhaus.enrich_ips(self.entity)

    def fetch_data(self):
        task_v = self.progress.add_task("Fetching data from Virustotal")
        self.progress.update(task_v, advance=50)
        self._fetch_vt_ip_address()
        self.progress.update(task_v, completed=100)

        task_i = self.progress.add_task(f"Fetching IP enrichments from {self._enricher.name}")
        self.progress.update(task_i, advance=50)
        self._fetch_ip_enrichments(self.entity)
        self.progress.update(task_i, completed=100)

        if self._urlhaus:
            task_u = self.progress.add_task(f"Fetching IP enrichments from {self._urlhaus.name}")
            self.progress.update(task_u, advance=50)
            self._fetch_urlhaus()
            self.progress.update(task_u, completed=100)

        if self._greynoise:
            task_g = self.progress.add_task(f"Fetching IP enrichments from {self._greynoise.name}")
            self.progress.update(task_g, advance=50)
            self._fetch_greynoise(self.entity)
            self.progress.update(task_g, completed=100)

        task_w = self.progress.add_task(f"Fetching IP whois from {self._whois.name}")
        self.progress.update(task_w, advance=50)
        self._fetch_whois()
        self.progress.update(task_w, completed=100)
