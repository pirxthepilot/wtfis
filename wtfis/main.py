import os
import sys

from dotenv import load_dotenv

from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.view import View


def main():
    # Load environment variables
    load_dotenv()

    # Run
    vt = VTClient(os.environ.get("VT_API_KEY"))
    domain = vt.get_domain(sys.argv[1])

    pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
    whois = pt.get_whois(sys.argv[1])

    console = View(whois, domain)
    console.print()
