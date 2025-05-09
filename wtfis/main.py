import argparse
import os
from argparse import Namespace
from pathlib import Path
from typing import Union

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.exceptions import WtfisException
from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.base import BaseView
from wtfis.ui.progress import get_progress
from wtfis.ui.view import DomainView, IpAddressView
from wtfis.utils import error_and_exit, is_ip
from wtfis.version import get_version


def parse_env() -> None:
    DEFAULT_ENV_FILE = Path().home() / ".env.wtfis"

    # Load the file
    load_dotenv(DEFAULT_ENV_FILE)

    # Exit if required environment variables don't exist
    for envvar in ("VT_API_KEY",):
        if not os.environ.get(envvar):
            error = f"Error: Environment variable {envvar} not set"
            if not DEFAULT_ENV_FILE.exists():
                error += (
                    f"\nEnv file {DEFAULT_ENV_FILE} was not found either. "
                    "Did you forget?"
                )
            error_and_exit(error)


def parse_args() -> Namespace:
    DEFAULT_MAX_RESOLUTIONS = 3

    parser = argparse.ArgumentParser()
    parser.add_argument("entity", help="Hostname, domain or IP")
    parser.add_argument(
        "-m",
        "--max-resolutions",
        metavar="N",
        help=(
            "Maximum number of resolutions to show "
            f"(default: {DEFAULT_MAX_RESOLUTIONS})"
        ),
        type=int,
        default=DEFAULT_MAX_RESOLUTIONS,
    )
    parser.add_argument(
        "-s", "--use-shodan", help="Use Shodan to enrich IPs", action="store_true"
    )
    parser.add_argument(
        "-g", "--use-greynoise", help="Enable Greynoise for IPs", action="store_true"
    )
    parser.add_argument(
        "-a", "--use-abuseipdb", help="Enable AbuseIPDB for IPs", action="store_true"
    )
    parser.add_argument(
        "-u",
        "--use-urlhaus",
        help="Enable URLhaus for IPs and domains",
        action="store_true",
    )
    parser.add_argument(
        "-n", "--no-color", help="Show output without colors", action="store_true"
    )
    parser.add_argument(
        "-1", "--one-column", help="Display results in one column", action="store_true"
    )
    parser.add_argument(
        "-V",
        "--version",
        help="Print version number",
        action="version",
        version=get_version(),
    )
    parsed = parser.parse_args()

    # Default overrides
    # If a default is set, then setting the flag as an argument _negates_ the effect
    for option in os.environ.get("WTFIS_DEFAULTS", "").split(" "):
        if option in ("-s", "--use-shodan"):
            parsed.use_shodan = not parsed.use_shodan
        elif option in ("-g", "--use-greynoise"):
            parsed.use_greynoise = not parsed.use_greynoise
        elif option in ("-a", "--use-abuseipdb"):
            parsed.use_abuseipdb = not parsed.use_abuseipdb
        elif option in ("-u", "--use-urlhaus"):
            parsed.use_urlhaus = not parsed.use_urlhaus
        elif option in ("-n", "--no-color"):
            parsed.no_color = not parsed.no_color
        elif option in ("-1", "--one-column"):
            parsed.one_column = not parsed.one_column

    # Validation
    if parsed.max_resolutions > 10:
        argparse.ArgumentParser().error("Maximum --max-resolutions value is 10")
    if parsed.use_shodan and not os.environ.get("SHODAN_API_KEY"):
        argparse.ArgumentParser().error("SHODAN_API_KEY is not set")
    if parsed.use_greynoise and not os.environ.get("GREYNOISE_API_KEY"):
        argparse.ArgumentParser().error("GREYNOISE_API_KEY is not set")
    if parsed.use_abuseipdb and not os.environ.get("ABUSEIPDB_API_KEY"):
        argparse.ArgumentParser().error("ABUSEIPDB_API_KEY is not set")
    if is_ip(parsed.entity) and parsed.max_resolutions != DEFAULT_MAX_RESOLUTIONS:
        argparse.ArgumentParser().error("--max-resolutions is not applicable to IPs")

    return parsed


def generate_entity_handler(
    args: Namespace,
    console: Console,
    progress: Progress,
) -> BaseHandler:
    # Virustotal client
    vt_client = VTClient(os.environ["VT_API_KEY"])

    # IP geolocation and ASN client selector
    # TODO: add more options
    ip_geoasn_client = IpWhoisClient()

    # Whois client selector
    # Order of use based on set envvars:
    #    1. IP2Whois (Domain only)
    #    2. Virustotal (fallback)
    if os.environ.get("IP2WHOIS_API_KEY") and not is_ip(args.entity):
        whois_client: Union[Ip2WhoisClient, VTClient] = Ip2WhoisClient(
            os.environ["IP2WHOIS_API_KEY"]
        )
    else:
        whois_client = vt_client

    shodan_client = (
        ShodanClient(os.environ["SHODAN_API_KEY"]) if args.use_shodan else None
    )

    # Greynoise client (optional)
    greynoise_client = (
        GreynoiseClient(os.environ["GREYNOISE_API_KEY"]) if args.use_greynoise else None
    )

    # AbuseIPDB client (optional)
    abuseipdb_client = (
        AbuseIpDbClient(os.environ["ABUSEIPDB_API_KEY"]) if args.use_abuseipdb else None
    )

    # URLhaus client (optional)
    urlhaus_client = UrlHausClient() if args.use_urlhaus else None

    # Domain / FQDN handler
    if not is_ip(args.entity):
        entity: BaseHandler = DomainHandler(
            entity=args.entity,
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=whois_client,
            shodan_client=shodan_client,
            greynoise_client=greynoise_client,
            abuseipdb_client=abuseipdb_client,
            urlhaus_client=urlhaus_client,
            max_resolutions=args.max_resolutions,
        )
    # IP address handler
    else:
        entity = IpAddressHandler(
            entity=args.entity,
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
    args: Namespace,
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
            max_resolutions=args.max_resolutions,
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
    # Load environment variables
    parse_env()

    # Args
    args = parse_args()

    # Instantiate the console
    console = Console(no_color=True) if args.no_color else Console()

    # Progress animation controller
    progress = get_progress(console)

    # Entity handler
    entity = generate_entity_handler(args, console, progress)

    # Fetch data
    with progress:
        entity.fetch_data()

    # Print fetch warnings, if any
    entity.print_warnings()

    # Output display
    view = generate_view(args, console, entity)

    # Finally, print output
    view.print(one_column=args.one_column)
