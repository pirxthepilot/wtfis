import abc

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
from typing import Callable, List, Optional, Union

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.urlhaus import UrlHausMap
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.theme import Theme
from wtfis.utils import error_and_exit, refang


def common_exception_handler(func: Callable) -> Callable:
    """ Decorator for handling common fetch errors """
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
    """ Decorator for handling calls that can fail open """
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
        ip_enricher_client: Union[IpWhoisClient, ShodanClient],
        whois_client: Union[Ip2WhoisClient, PTClient, VTClient],
        greynoise_client: Optional[GreynoiseClient],
        urlhaus_client: Optional[UrlHausClient],
    ):
        # Process-specific
        self.entity = refang(entity)
        self.console = console
        self.progress = progress

        # Clients
        self._vt = vt_client
        self._enricher = ip_enricher_client
        self._whois = whois_client
        self._greynoise = greynoise_client
        self._urlhaus = urlhaus_client

        # Dataset containers
        self.vt_info:   Union[Domain, IpAddress]
        self.ip_enrich: Union[IpWhoisMap, ShodanIpMap] = IpWhoisMap.empty()
        self.whois:     WhoisBase
        self.greynoise: GreynoiseIpMap = GreynoiseIpMap.empty()
        self.urlhaus:  UrlHausMap = UrlHausMap.empty()

        # Warning messages container
        self.warnings: List[str] = []

    @abc.abstractmethod
    def fetch_data(self) -> None:
        """ Main method that controls what get fetched """
        return NotImplemented  # type: ignore  # pragma: no coverage

    @common_exception_handler
    @failopen_exception_handler("_enricher")
    def _fetch_ip_enrichments(self, *ips: str) -> None:
        self.ip_enrich = self._enricher.enrich_ips(*ips)

    @common_exception_handler
    @failopen_exception_handler("_greynoise")
    def _fetch_greynoise(self, *ips: str) -> None:
        if self._greynoise:
            self.greynoise = self._greynoise.enrich_ips(*ips)

    @common_exception_handler
    def _fetch_whois(self) -> None:
        # Let continue if rate limited
        try:
            self.whois = self._whois.get_whois(self.entity)
        except HTTPError as e:
            if e.response.status_code == 429:
                self.warnings.append(f"Could not fetch Whois: {e}")
            else:  # pragma: no coverage
                raise

    def print_warnings(self):
        for message in self.warnings:
            self.console.print(f"WARN: {message}", style=Theme().warn)
