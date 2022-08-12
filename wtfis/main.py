import argparse
import os

from dotenv import load_dotenv
from pathlib import Path
from pydantic import ValidationError
from requests.exceptions import HTTPError, JSONDecodeError
from rich.console import Console

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.utils import error_and_exit
from wtfis.ui.progress import get_progress
from wtfis.ui.view import View
from wtfis.version import get_version


def parse_env():
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


def parse_args():
    DEFAULT_MAX_RESOLUTIONS = 3

    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="Hostname or domain")
    parser.add_argument(
        "-m", "--max-resolutions", metavar="N",
        help=f"Maximum number of resolutions to show (default: {DEFAULT_MAX_RESOLUTIONS})",
        type=int,
        default=DEFAULT_MAX_RESOLUTIONS
    )
    parser.add_argument("-n", "--no-color", help="Show output without colors", action="store_true")
    parser.add_argument("-1", "--one-column", help="Display results in one column", action="store_true")
    parser.add_argument(
        "-V", "--version",
        help="Print version number",
        action="version",
        version=get_version()
    )

    # Validation
    parsed = parser.parse_args()
    if parsed.max_resolutions > 10:
        argparse.ArgumentParser().error("Maximum --max-resolutions value is 10")

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
            domain = vt.get_domain(args.hostname)
            progress.update(task1, advance=33)

            # Resolutions and IP enrichments
            if args.max_resolutions != 0:
                resolutions = vt.get_domain_resolutions(args.hostname)
                progress.update(task1, advance=33)

                task2 = progress.add_task("Fetching IP enrichments from IPWhois")
                ipwhois = IpWhoisClient()
                progress.update(task2, advance=50)
                ip_enrich = ipwhois.bulk_get_ipwhois(resolutions, args.max_resolutions)
                progress.update(task2, advance=50)
            else:
                resolutions = None
                ip_enrich = []
            progress.update(task1, completed=100)

            # Whois
            # Use Passivetotal if relevant environment variables exist, otherwise keep using VT
            if os.environ.get("PT_API_USER") and os.environ.get("PT_API_KEY"):
                task3 = progress.add_task("Fetching domain whois from Passivetotal")
                pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
                progress.update(task3, advance=50)
                whois = pt.get_whois(args.hostname)
                progress.update(task3, advance=50)
            else:
                task3 = progress.add_task("Fetching domain whois from Virustotal")
                whois = vt.get_domain_whois(args.hostname)
                progress.update(task3, advance=100)
        except (HTTPError, JSONDecodeError) as e:
            progress.stop()
            error_and_exit(f"Error fetching data: {e}")
        except ValidationError as e:
            progress.stop()
            error_and_exit(f"Data model validation error: {e}")

    # Output
    view = View(
        console,
        domain,
        resolutions,
        whois,
        ip_enrich,
        max_resolutions=args.max_resolutions,
    )
    view.print(one_column=args.one_column)
