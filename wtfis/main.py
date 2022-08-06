import argparse
import os

from dotenv import load_dotenv
from pathlib import Path
from pydantic import ValidationError
from requests.exceptions import HTTPError, JSONDecodeError

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.utils import error_and_exit
from wtfis.view import View


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
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="Hostname or domain")
    parser.add_argument("-n", "--no-color", help="Show output without colors", action="store_true")
    parser.add_argument("-m", "--max-resolutions", help="Maximum number of resolutions to show", type=int, default=3)
    parser.add_argument("-1", "--one-column", help="Display results in one column", action="store_true")

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

    # Fetch data
    try:
        # Virustotal domain
        vt = VTClient(os.environ.get("VT_API_KEY"))
        domain = vt.get_domain(args.hostname)

        # Resolutions and IP enrichments
        if args.max_resolutions != 0:
            resolutions = vt.get_domain_resolutions(args.hostname)

            ipwhois = IpWhoisClient()
            ip_enrich = ipwhois.bulk_get_ipwhois(resolutions, args.max_resolutions)
        else:
            resolutions = None
            ip_enrich = []

        # Whois
        # Use Passivetotal if relevant environment variables exist, otherwise keep using VT
        if os.environ.get("PT_API_USER") and os.environ.get("PT_API_KEY"):
            pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
            whois = pt.get_whois(args.hostname)
        else:
            whois = vt.get_domain_whois(args.hostname)
    except (HTTPError, JSONDecodeError) as e:
        error_and_exit(f"Error fetching data: {e}")
    except ValidationError as e:
        error_and_exit(f"Data model validation error: {e}")

    # Output
    console = View(
        domain,
        resolutions,
        whois,
        ip_enrich,
        max_resolutions=args.max_resolutions,
        no_color=args.no_color,
    )
    console.print(one_column=args.one_column)
