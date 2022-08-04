import argparse
import os

from dotenv import load_dotenv

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.view import View


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="Hostname or domain")
    parser.add_argument("-n", "--no-color", help="Show output without colors", action="store_true")
    parser.add_argument("-m", "--max-resolutions", help="Maximum number of resolutions to show", type=int, default=3)

    return parser.parse_args()


def main():
    # Load environment variables
    load_dotenv()

    # Args
    args = parse_args()
    if args.max_resolutions > 10:
        argparse.ArgumentParser().error("Maximum --max-resolutions value is 10")

    # Virustotal
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

    # Passivetotal
    pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
    whois = pt.get_whois(args.hostname)

    # Output
    console = View(
        whois,
        domain,
        resolutions,
        ip_enrich,
        max_resolutions=args.max_resolutions,
        no_color=args.no_color,
    )
    console.print()
