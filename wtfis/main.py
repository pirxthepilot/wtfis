import os
from typing import Union

from rich.console import Console
from rich.progress import Progress

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.config import Config
from wtfis.exceptions import WtfisException
from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.base import BaseView
from wtfis.ui.progress import get_progress
from wtfis.ui.view import DomainView, IpAddressView
from wtfis.utils import is_ip


def generate_entity_handler(
    config: Config,
    console: Console,
    progress: Progress,
) -> BaseHandler:
    # Virustotal client
    vt_client = VTClient(config.vt_api_key)

    # IP geolocation and ASN client selector
    # TODO: add more options
    ip_geoasn_client = IpWhoisClient()

    # Whois client selector
    # Order of use based on set envvars:
    #    1. IP2Whois (Domain only)
    #    2. Virustotal (fallback)
    if config.ip2whois_api_key and not is_ip(config.entity):
        whois_client: Union[Ip2WhoisClient, VTClient] = Ip2WhoisClient(
            config.ip2whois_api_key
        )
    else:
        whois_client = vt_client

    shodan_client = (
        ShodanClient(os.environ["SHODAN_API_KEY"]) if config.use_shodan else None
    )

    # Greynoise client (optional)
    greynoise_client = (
        GreynoiseClient(config.greynoise_api_key) if config.use_greynoise else None
    )

    # AbuseIPDB client (optional)
    abuseipdb_client = (
        AbuseIpDbClient(config.abuseipdb_api_key) if config.use_abuseipdb else None
    )

    # URLhaus client (optional)
    urlhaus_client = UrlHausClient() if config.use_urlhaus else None

    # Domain / FQDN handler
    if not is_ip(config.entity):
        entity: BaseHandler = DomainHandler(
            entity=config.entity,
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=whois_client,
            shodan_client=shodan_client,
            greynoise_client=greynoise_client,
            abuseipdb_client=abuseipdb_client,
            urlhaus_client=urlhaus_client,
            max_resolutions=config.max_resolutions,
        )
    # IP address handler
    else:
        entity = IpAddressHandler(
            entity=config.entity,
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=whois_client,
            shodan_client=shodan_client,
            greynoise_client=greynoise_client,
            abuseipdb_client=abuseipdb_client,
            urlhaus_client=urlhaus_client,
        )

    return entity


def generate_view(
    config: Config,
    console: Console,
    entity: BaseHandler,
) -> BaseView:
    # Output display
    if isinstance(entity, DomainHandler) and isinstance(entity.vt_info, Domain):
        view: BaseView = DomainView(
            console,
            entity.vt_info,
            entity.resolutions,
            entity.geoasn,
            entity.whois,
            entity.shodan,
            entity.greynoise,
            entity.abuseipdb,
            entity.urlhaus,
            max_resolutions=config.max_resolutions,
        )
    elif isinstance(entity, IpAddressHandler) and isinstance(entity.vt_info, IpAddress):
        view = IpAddressView(
            console,
            entity.vt_info,
            entity.geoasn,
            entity.whois,
            entity.shodan,
            entity.greynoise,
            entity.abuseipdb,
            entity.urlhaus,
        )
    else:
        raise WtfisException("Unsupported entity!")

    return view


def main():
    # Load config
    config = Config()

    # Instantiate the console
    console = Console(no_color=True) if config.no_color else Console()

    # Progress animation controller
    progress = get_progress(console)

    # Entity handler
    entity = generate_entity_handler(config, console, progress)

    # Fetch data
    with progress:
        entity.fetch_data()

    # Print fetch warnings, if any
    entity.print_warnings()

    # Output display
    view = generate_view(config, console, entity)

    # Finally, print output
    view.print(one_column=config.one_column)
