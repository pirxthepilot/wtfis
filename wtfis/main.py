import os
import sys

from dotenv import load_dotenv

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.view import View


def main():
    # Load environment variables
    load_dotenv()

    # Temp variable
    max_resolutions = 3

    # Run
    vt = VTClient(os.environ.get("VT_API_KEY"))
    domain = vt.get_domain(sys.argv[1])
    resolutions = vt.get_domain_resolutions(sys.argv[1])

    ipwhois = IpWhoisClient()
    ip_enrich = ipwhois.bulk_get_ipwhois(resolutions, max_resolutions)

    pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
    whois = pt.get_whois(sys.argv[1])

    console = View(whois, domain, resolutions, max_resolutions, ip_enrich)
    console.print()
