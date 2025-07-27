"""
Global config
"""

import argparse
import os
from argparse import Namespace
from pathlib import Path
from typing import Optional, Union

from dotenv import load_dotenv

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2location import Ip2LocationClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipinfo import IpInfoClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.types import IpGeoAsnClientType
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.utils import error_and_exit, is_ip
from wtfis.version import get_version

ABUSEIPDB_API_KEY_VAR = "ABUSEIPDB_API_KEY"
GREYNOISE_API_KEY_VAR = "GREYNOISE_API_KEY"
IP2LOCATION_API_KEY_VAR = "IP2LOCATION_API_KEY"
IP2WHOIS_API_KEY_VAR = "IP2WHOIS_API_KEY"
SHODAN_API_KEY_VAR = "SHODAN_API_KEY"
URLHAUS_API_KEY_VAR = "URLHAUS_API_KEY"
VT_API_KEY_VAR = "VT_API_KEY"
WTFIS_DEFAULTS_VAR = "WTFIS_DEFAULTS"
GEOLOCATION_SERVICE_VAR = "GEOLOCATION_SERVICE"


def parse_env() -> None:
    DEFAULT_ENV_FILE = Path().home() / ".env.wtfis"

    # Load the file
    load_dotenv(DEFAULT_ENV_FILE)

    # Exit if required environment variables don't exist
    for envvar in (VT_API_KEY_VAR,):
        if not os.environ.get(envvar):
            error = f"Error: Environment variable {envvar} not set"
            if not DEFAULT_ENV_FILE.exists():
                error += (
                    f"\nEnv file {DEFAULT_ENV_FILE} was not found either. "
                    "Did you forget?"
                )
            error_and_exit(error)


def parse_args() -> Namespace:
    GEOLOCATION_SERVICES = (
        "ip2location",
        "ipinfo",
        "ipwhois",
    )
    DEFAULT_GEOLOCATION_SERVICE = "ipwhois"
    DEFAULT_MAX_RESOLUTIONS = 3

    parser = argparse.ArgumentParser()
    parser.add_argument("entity", help="Hostname, domain or IP")
    parser.add_argument(
        "-A",
        "--all",
        help="Enable all possible enrichments",
        action="store_true",
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
    parser.add_argument(
        "--geolocation-service",
        choices=GEOLOCATION_SERVICES,
        help=f"Geolocation service to use (default: {DEFAULT_GEOLOCATION_SERVICE})",
    )
    parsed = parser.parse_args()

    # Default overrides
    # If a default is set, then setting a boolean flag as an argument _negates_ the effect.
    # Negation does not apply to non-boolean flags (e.g. --max-resolution)
    for option in os.environ.get(WTFIS_DEFAULTS_VAR, "").split(" "):
        if option in ("-A", "--all"):
            parsed.all = not parsed.all
        elif option in ("-s", "--use-shodan"):
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

    # Geolocation service
    # Commandline flag takes precedence over env file or variable
    # Set the default here if no service is provided
    parsed.geolocation_service = (
        parsed.geolocation_service
        or os.environ.get(GEOLOCATION_SERVICE_VAR)
        or DEFAULT_GEOLOCATION_SERVICE
    )

    # Validations
    if parsed.max_resolutions > 10:
        argparse.ArgumentParser().error("Maximum --max-resolutions value is 10")
    if is_ip(parsed.entity) and parsed.max_resolutions != DEFAULT_MAX_RESOLUTIONS:
        argparse.ArgumentParser().error("--max-resolutions is not applicable to IPs")

    if parsed.use_shodan and not os.environ.get(SHODAN_API_KEY_VAR):
        argparse.ArgumentParser().error(f"{SHODAN_API_KEY_VAR} is not set")
    if parsed.use_greynoise and not os.environ.get(GREYNOISE_API_KEY_VAR):
        argparse.ArgumentParser().error(f"{GREYNOISE_API_KEY_VAR} is not set")
    if parsed.use_abuseipdb and not os.environ.get(ABUSEIPDB_API_KEY_VAR):
        argparse.ArgumentParser().error(f"{ABUSEIPDB_API_KEY_VAR} is not set")
    if parsed.use_urlhaus and not os.environ.get(URLHAUS_API_KEY_VAR):
        argparse.ArgumentParser().error(f"{URLHAUS_API_KEY_VAR} is not set")

    if parsed.geolocation_service not in GEOLOCATION_SERVICES:
        argparse.ArgumentParser().error(
            f"Invalid geolocation service: {parsed.geolocation_service}. "
            f"Valid services are: {', '.join(GEOLOCATION_SERVICES)}"
        )
    if parsed.geolocation_service == "ip2location" and not os.environ.get(
        IP2LOCATION_API_KEY_VAR
    ):
        argparse.ArgumentParser().error(f"{IP2LOCATION_API_KEY_VAR} is not set")

    if parsed.all and (
        parsed.use_shodan
        or parsed.use_greynoise
        or parsed.use_abuseipdb
        or parsed.use_urlhaus
    ):
        argparse.ArgumentParser().error(
            "--use-* flags are not accepted when the " "--all/-A flag is set"
        )

    return parsed


class Config:
    def __init__(self) -> None:
        # Load environment variables
        parse_env()

        # Get arg values
        self.args: Namespace = parse_args()

        # Creds
        self.abuseipdb_api_key = os.environ.get(ABUSEIPDB_API_KEY_VAR, "")
        self.greynoise_api_key = os.environ.get(GREYNOISE_API_KEY_VAR, "")
        self.ip2location_api_key = os.environ.get(IP2LOCATION_API_KEY_VAR, "")
        self.ip2whois_api_key = os.environ.get(IP2WHOIS_API_KEY_VAR, "")
        self.shodan_api_key = os.environ.get(SHODAN_API_KEY_VAR, "")
        self.urlhaus_api_key = os.environ.get(URLHAUS_API_KEY_VAR, "")
        self.vt_api_key = os.environ.get(VT_API_KEY_VAR, "")

    @property
    def entity(self) -> str:
        return self.args.entity

    @property
    def max_resolutions(self) -> int:
        return self.args.max_resolutions

    @property
    def no_color(self) -> bool:
        return self.args.no_color

    @property
    def one_column(self) -> bool:
        return self.args.one_column

    @property
    def vt_client(self) -> VTClient:
        return VTClient(self.vt_api_key)

    @property
    def ip_geoasn_client(self) -> IpGeoAsnClientType:
        # IP geolocation and ASN client selector
        if self.args.geolocation_service == "ip2location":
            return Ip2LocationClient(self.ip2location_api_key)
        if self.args.geolocation_service == "ipinfo":
            return IpInfoClient()
        return IpWhoisClient()

    @property
    def whois_client(self) -> Union[Ip2WhoisClient, VTClient]:
        # Whois client selector
        # Order of use based on set envvars:
        #    1. IP2Whois (Domain only)
        #    2. Virustotal (fallback)
        if self.ip2whois_api_key and not is_ip(self.entity):
            return Ip2WhoisClient(self.ip2whois_api_key)
        return self.vt_client

    @property
    def abuseipdb_client(self) -> Optional[AbuseIpDbClient]:
        if (self.args.use_abuseipdb or self.args.all) and bool(self.abuseipdb_api_key):
            return AbuseIpDbClient(self.abuseipdb_api_key)
        return None

    @property
    def greynoise_client(self) -> Optional[GreynoiseClient]:
        if (self.args.use_greynoise or self.args.all) and bool(self.greynoise_api_key):
            return GreynoiseClient(self.greynoise_api_key)
        return None

    @property
    def shodan_client(self) -> Optional[ShodanClient]:
        if (self.args.use_shodan or self.args.all) and bool(self.shodan_api_key):
            return ShodanClient(self.shodan_api_key)
        return None

    @property
    def urlhaus_client(self) -> Optional[UrlHausClient]:
        if self.args.use_urlhaus or self.args.all and bool(self.urlhaus_api_key):
            return UrlHausClient(self.urlhaus_api_key)
        return None
