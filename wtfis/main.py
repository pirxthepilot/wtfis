import datetime
import os
import sys

from dotenv import load_dotenv
from prompt_toolkit import HTML, print_formatted_text as print

from wtfis.clients.passivetotal import PTClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.virustotal import Domain


def iso_date(unix_time: int) -> str:
    return datetime.datetime.utcfromtimestamp(unix_time).isoformat()


def main():
    # Load environment variables
    load_dotenv()

    # Run
    vt = VTClient(os.environ.get("VT_API_KEY"))
    domain = Domain.parse_obj(vt.get_domain(sys.argv[1]))

    print(HTML(f"<b>Reputation:</b> {domain.reputation}"))
    print(HTML(f"<b>Registrar:</b> {domain.registrar}"))
    print(HTML(f"<b>Last DNS Records Date:</b> {iso_date(domain.last_dns_records_date)}"))

    pt = PTClient(os.environ.get("PT_API_USER"), os.environ.get("PT_API_KEY"))
    passive = pt.get_whois(sys.argv[1])

    print(passive)
