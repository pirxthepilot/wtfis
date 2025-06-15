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
        yield "Fetching data from Virustotal", 50
        self._fetch_vt_ip_address()

        yield f"Fetching IP location and ASN from {self._geoasn.name}", 50
        self._fetch_geoasn(self.entity)

        if self._shodan:
            yield f"Fetching IP data from {self._shodan.name}", 50
            self._fetch_shodan(self.entity)

        if self._urlhaus:
            yield f"Fetching IP data from {self._urlhaus.name}", 50
            self._fetch_urlhaus()

        if self._greynoise:
            yield f"Fetching IP data from {self._greynoise.name}", 50
            self._fetch_greynoise(self.entity)

        if self._abuseipdb:
            yield f"Fetching IP data from {self._abuseipdb.name}", 50
            self._fetch_abuseipdb(self.entity)

        yield f"Fetching IP whois from {self._whois.name}", 50
        self._fetch_whois()
