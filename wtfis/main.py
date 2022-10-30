import argparse
import os

from argparse import Namespace
from dotenv import load_dotenv
from pathlib import Path
from pydantic import ValidationError
from requests.exceptions import HTTPError, JSONDecodeError
from rich.console import Console
from shodan.exception import APIError

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.virustotal import Domain
from wtfis.utils import error_and_exit, is_ip, refang
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
        try:
            # Virustotal domain
            task1 = progress.add_task("Fetching data from Virustotal")
            vt = VTClient(os.environ.get("VT_API_KEY"))
            progress.update(task1, advance=33)
            if is_ip(args.entity):
                entity = vt.get_ip_address(refang(args.entity))
            else:
                entity = vt.get_domain(args.entity)
            progress.update(task1, advance=33)

            # Domain resolutions and IP enrichments
            if isinstance(entity, Domain):
                if args.max_resolutions != 0:
                    resolutions = vt.get_domain_resolutions(args.entity)
                    progress.update(task1, completed=100)

                    if args.use_shodan:
                        # Shodan
                        task2 = progress.add_task("Fetching IP enrichments from Shodan")
                        shodan = ShodanClient(os.environ.get("SHODAN_API_KEY"))
                        progress.update(task2, advance=50)
                        ip_enrich = shodan.bulk_get_ip(resolutions, args.max_resolutions)
                        progress.update(task2, advance=50)
                    else:
                        # IPWhois
                        task2 = progress.add_task("Fetching IP enrichments from IPWhois")
                        ipwhois = IpWhoisClient()
                        progress.update(task2, advance=50)
                        ip_enrich = ipwhois.bulk_get_ipwhois(resolutions, args.max_resolutions)
                        progress.update(task2, advance=50)
                else:
                    resolutions = None
                    ip_enrich = []

            # IP address enrichments
            else:
                progress.update(task1, completed=100)

                if args.use_shodan:
                    # Shodan
                    task2 = progress.add_task("Fetching IP enrichments from Shodan")
                    shodan = ShodanClient(os.environ.get("SHODAN_API_KEY"))
                    progress.update(task2, advance=50)
                    ip_enrich = shodan.single_get_ip(entity.data.id_)
                    progress.update(task2, advance=50)
                else:
                    # IPWhois
                    task2 = progress.add_task("Fetching IP enrichments from IPWhois")
                    ipwhois = IpWhoisClient()
                    progress.update(task2, advance=50)
                    ip_enrich = ipwhois.single_get_ipwhois(entity.data.id_)
                    progress.update(task2, advance=50)

            # Whois
            # Use Passivetotal if relevant environment variables exist, otherwise keep using VT
            if os.environ.get("PT_API_USER") and os.environ.get("PT_API_KEY"):
                task3 = progress.add_task("Fetching domain whois from Passivetotal")
                pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
                progress.update(task3, advance=50)
                whois = pt.get_whois(entity.data.id_)
                progress.update(task3, advance=50)
            else:
                task3 = progress.add_task("Fetching domain whois from Virustotal")
                whois = vt.get_whois(entity.data.id_)
                progress.update(task3, advance=100)
        except (HTTPError, JSONDecodeError, APIError) as e:
            progress.stop()
            error_and_exit(f"Error fetching data: {e}")
        except ValidationError as e:
            progress.stop()
            error_and_exit(f"Data model validation error: {e}")

    # Output
    if isinstance(entity, Domain):
        view = DomainView(
            console,
            entity,
            resolutions,
            whois,
            ip_enrich,
            max_resolutions=args.max_resolutions,
        )
    else:
        view = IpAddressView(
            console,
            entity,
            whois,
            ip_enrich,
        )
    view.print(one_column=args.one_column)
