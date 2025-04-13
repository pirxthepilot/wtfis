from pathlib import Path
from typing import Optional

import pytest
from rich.console import RenderableType
from rich.text import Span, Text

from wtfis.models.abuseipdb import AbuseIpDb
from wtfis.models.greynoise import GreynoiseIp
from wtfis.models.ipwhois import IpWhois
from wtfis.models.shodan import ShodanIp
from wtfis.models.urlhaus import UrlHaus


class TestTheme:
    """Expected theme values for the tests"""

    panel_title = "bold yellow"
    heading_h1 = "bold bright_green on dark_green"
    heading_h2 = "bold yellow"
    table_field = "bold bright_magenta"
    table_value = "not bold default"
    popularity_source = "bright_cyan"
    inline_stat = "cyan"
    vendor_list = "cyan"
    nameserver_list = "bright_blue"
    disclaimer = "italic white on red"
    tags = "bright_white on black"
    tags_green = "bright_green on black"
    tags_red = "bright_red on black"
    product = "orange_red1"
    port = "bright_cyan"
    transport = "cyan"
    footer = "cyan"
    info = "bold green"
    warn = "bold yellow"
    error = "bold red"
    timestamp_date = "not bold default"
    timestamp_t = "dim bright_white"
    timestamp_time = "dim default"
    timestamp_z = "dim bright_white"
    asn_org = "bright_white"
    whois_org = "bright_cyan"
    urlhaus_bl_name = "bright_cyan"
    urlhaus_bl_low = "bright_white on green"
    urlhaus_bl_med = "black on yellow"
    urlhaus_bl_high = "bright_white on red"


def open_test_data(fname: str) -> str:
    path = Path(__file__).parent.resolve() / "test_data" / fname
    with open(path) as f:
        return f.read()


def abuseipdb_get_ip(ip, pool) -> AbuseIpDb:
    """Mock replacement for AbuseIpDbClient()._get_ip()"""
    return AbuseIpDb.model_validate(pool[ip])


def greynoise_get(ip, pool) -> GreynoiseIp:
    """Mock replacement for GreynoiseClient().get_ip()"""
    return GreynoiseIp.model_validate(pool[ip])


def ipwhois_get(ip, pool) -> IpWhois:
    """Mock replacement for IpWhoisClient().get_ipwhois()"""
    return IpWhois.model_validate(pool[ip])


def shodan_get_ip(ip, pool) -> ShodanIp:
    """Mock replacement for ShodanClient().get_ip()"""
    return ShodanIp.model_validate(pool[ip])


def urlhaus_get_host(entity, pool) -> UrlHaus:
    """Mock replacement for UrlHausClient()._get_host()"""
    return UrlHaus.model_validate(pool[entity])


def timestamp_text(ts) -> Optional[RenderableType]:
    """Standard timestamp formatting"""
    theme = TestTheme()
    return Text(
        ts,
        style=theme.timestamp_date,
        spans=[
            Span(10, 11, theme.timestamp_t),
            Span(11, 19, theme.timestamp_time),
            Span(19, 20, theme.timestamp_z),
        ],
    )


@pytest.fixture(scope="module")
def test_data():
    return open_test_data


@pytest.fixture(scope="module")
def theme():
    return TestTheme()


@pytest.fixture(scope="module")
def mock_abuseipdb_get():
    return abuseipdb_get_ip


@pytest.fixture(scope="module")
def mock_greynoise_get():
    return greynoise_get


@pytest.fixture(scope="module")
def mock_ipwhois_get():
    return ipwhois_get


@pytest.fixture(scope="module")
def mock_shodan_get_ip():
    return shodan_get_ip


@pytest.fixture(scope="module")
def mock_urlhaus_get():
    return urlhaus_get_host


@pytest.fixture(scope="module")
def display_timestamp():
    return timestamp_text
