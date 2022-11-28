import argparse
import os

from argparse import Namespace
from dotenv import load_dotenv
from pathlib import Path
from rich.console import Console

from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.utils import error_and_exit, is_ip
from wtfis.ui.progress import get_progress
from wtfis.ui.view import DomainView, IpAddressView
from wtfis.version import get_version


def parse_env() -> None:
    DEFAULT_ENV_FILE = Path().home() / ".env.wtfis"

    # Load the file
    load_dotenv(DEFAULT_ENV_FILE)

    # Exit if required environment variables don't exist
    for envvar in (
        "VT_API_KEY",
    ):
        if not os.environ.get(envvar):
            error = f"Error: Environment variable {envvar} not set"
            if not DEFAULT_ENV_FILE.exists():
                error = error + f"\nEnv file {DEFAULT_ENV_FILE} was not found either. Did you forget?"
            error_and_exit(error)


def parse_args() -> Namespace:
    DEFAULT_MAX_RESOLUTIONS = 3

    parser = argparse.ArgumentParser()
    parser.add_argument("entity", help="Hostname, domain or IP")
    parser.add_argument(
        "-m", "--max-resolutions", metavar="N",
        help=f"Maximum number of resolutions to show (default: {DEFAULT_MAX_RESOLUTIONS})",
        type=int,
        default=DEFAULT_MAX_RESOLUTIONS
    )
    parser.add_argument("-s", "--use-shodan", help="Use Shodan to enrich IPs", action="store_true")
    parser.add_argument("-n", "--no-color", help="Show output without colors", action="store_true")
    parser.add_argument("-1", "--one-column", help="Display results in one column", action="store_true")
    parser.add_argument(
        "-V", "--version",
        help="Print version number",
        action="version",
        version=get_version()
    )
    parsed = parser.parse_args()

    # Default overrides
    # If a default is set, then setting the flag as an argument _negates_ the effect
    for option in os.environ.get("WTFIS_DEFAULTS", "").split(" "):
        if option in ("-s", "--use-shodan"):
            parsed.use_shodan = not parsed.use_shodan
        elif option in ("-n", "--no-color"):
            parsed.no_color = not parsed.no_color
        elif option in ("-1", "--one-column"):
            parsed.one_column = not parsed.one_column

    # Validation
    if parsed.max_resolutions > 10:
        argparse.ArgumentParser().error("Maximum --max-resolutions value is 10")
    if parsed.use_shodan and not os.environ.get("SHODAN_API_KEY"):
        argparse.ArgumentParser().error("SHODAN_API_KEY is not set")
    if is_ip(parsed.entity) and parsed.max_resolutions != DEFAULT_MAX_RESOLUTIONS:
        argparse.ArgumentParser().error("--max-resolutions is not applicable to IPs")

    return parsed


def main():
    # Load environment variables
    parse_env()

    # Args
    args = parse_args()

    # Instantiate the console
    console = Console(no_color=True) if args.no_color else Console()

    # Progress animation controller
    progress = get_progress(console)

    # Fetch data
    with progress:
        # Virustotal client
        vt_client = VTClient(os.environ.get("VT_API_KEY"))

        # IP enrichment client selector
        enricher_client = (
            ShodanClient(os.environ.get("SHODAN_API_KEY"))
            if args.use_shodan
            else IpWhoisClient()
        )

        # Whois client selector
        # Order of use based on set envvars:
        #    1. Passivetotal
        #    2. IP2Whois (Domain only)
        #    2. Virustotal (fallback)
        if os.environ.get("PT_API_USER") and os.environ.get("PT_API_KEY"):
            whois_client = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
        elif os.environ.get("IP2WHOIS_API_KEY") and not is_ip(args.entity):
            whois_client = Ip2WhoisClient(os.environ.get("IP2WHOIS_API_KEY"))
        else:
            whois_client = vt_client

        # Domain / FQDN handler
        if not is_ip(args.entity):
            entity = DomainHandler(
                entity=args.entity,
                console=console,
                progress=progress,
                vt_client=vt_client,
                ip_enricher_client=enricher_client,
                whois_client=whois_client,
                max_resolutions=args.max_resolutions,
            )
        # IP address handler
        else:
            entity = IpAddressHandler(
                entity=args.entity,
                console=console,
                progress=progress,
                vt_client=vt_client,
                ip_enricher_client=enricher_client,
                whois_client=whois_client,
            )

        # Data fetching proper
        entity.fetch_data()

    # Print warnings, if any
    entity.print_warnings()

    # Output display
    if isinstance(entity, DomainHandler):
        view = DomainView(
            console,
            entity.vt_info,
            entity.resolutions,
            entity.whois,
            entity.ip_enrich,
            max_resolutions=args.max_resolutions,
        )
    else:
        view = IpAddressView(
            console,
            entity.vt_info,
            entity.whois,
            entity.ip_enrich,
        )
    view.print(one_column=args.one_column)
