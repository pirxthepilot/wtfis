import abc
from typing import Callable, List, Optional, Union

from pydantic import ValidationError
from requests.exceptions import (
    ConnectionError,
    HTTPError,
    JSONDecodeError,
    RequestException,
    Timeout,
)
from rich.console import Console
from rich.progress import Progress
from shodan.exception import APIError

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.types import IpGeoAsnClientType, IpWhoisClientType
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.abuseipdb import AbuseIpDbMap
from wtfis.models.base import WhoisBase
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.types import IpGeoAsnMapType
from wtfis.models.urlhaus import UrlHausMap
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.theme import Theme
from wtfis.utils import error_and_exit, refang


def common_exception_handler(func: Callable) -> Callable:
    """Decorator for handling common fetch errors"""

    def inner(*args, **kwargs) -> None:
        progress: Progress = args[0].progress  # args[0] is the method's self input
        try:
            func(*args, **kwargs)
        except (APIError, ConnectionError, HTTPError, JSONDecodeError, Timeout) as e:
            progress.stop()
            error_and_exit(f"Error fetching data: {e}")
        except ValidationError as e:
            progress.stop()
            error_and_exit(f"Data model validation error: {e}")

    return inner


def failopen_exception_handler(client_attr_name: str) -> Callable:
    """Decorator for handling calls that can fail open"""

    def inner(func):
        def wrapper(*args, **kwargs) -> None:
            client = getattr(args[0], client_attr_name)  # Client obj who made the call
            warnings: List[str] = args[0].warnings
            try:
                func(*args, **kwargs)
            except (APIError, RequestException) as e:
                # Add warning
                warnings.append(f"Could not fetch {client.name}: {e}")

        return wrapper

    return inner


class BaseHandler(abc.ABC):
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
    ):
        # Process-specific
        self.entity = refang(entity)
        self.console = console
        self.progress = progress

        # Clients
        self._vt = vt_client
        self._geoasn = ip_geoasn_client
        self._whois = whois_client
        self._shodan = shodan_client
        self._greynoise = greynoise_client
        self._abuseipdb = abuseipdb_client
        self._urlhaus = urlhaus_client

        # Dataset containers
        self.vt_info: Union[Domain, IpAddress]
        self.geoasn: IpGeoAsnMapType = IpWhoisMap.empty()  # Default to ipwhois
        self.whois: WhoisBase = WhoisBase()
        self.shodan: ShodanIpMap = ShodanIpMap.empty()
        self.greynoise: GreynoiseIpMap = GreynoiseIpMap.empty()
        self.abuseipdb: AbuseIpDbMap = AbuseIpDbMap.empty()
        self.urlhaus: UrlHausMap = UrlHausMap.empty()

        # Warning messages container
        self.warnings: List[str] = []

    @abc.abstractmethod
    def fetch_data(self) -> None:
        """Main method that controls what get fetched"""
        return NotImplemented  # type: ignore  # pragma: no coverage

    @common_exception_handler
    @failopen_exception_handler("_geoasn")
    def _fetch_geoasn(self, *ips: str) -> None:
        self.geoasn = self._geoasn.enrich_ips(*ips)

    @common_exception_handler
    @failopen_exception_handler("_shodan")
    def _fetch_shodan(self, *ips: str) -> None:
        if self._shodan:
            self.shodan = self._shodan.enrich_ips(*ips)

    @common_exception_handler
    @failopen_exception_handler("_greynoise")
    def _fetch_greynoise(self, *ips: str) -> None:
        if self._greynoise:
            self.greynoise = self._greynoise.enrich_ips(*ips)

    @common_exception_handler
    @failopen_exception_handler("_abuseipdb")
    def _fetch_abuseipdb(self, *ips: str) -> None:
        if self._abuseipdb:
            self.abuseipdb = self._abuseipdb.enrich_ips(*ips)

    @common_exception_handler
    @failopen_exception_handler("_whois")
    def _fetch_whois(self) -> None:
        self.whois = self._whois.get_whois(self.entity)

    def print_warnings(self):
        for message in self.warnings:
            self.console.print(f"WARN: {message}", style=Theme().warn)
