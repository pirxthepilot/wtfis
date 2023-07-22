import pytest
from pathlib import Path
from typing import Optional

from rich.console import RenderableType
from rich.text import Span, Text

from wtfis.models.greynoise import GreynoiseIp
from wtfis.models.ipwhois import IpWhois
from wtfis.models.shodan import ShodanIp


class TestTheme:
    """ Expected theme values for the tests """
    nameserver_list = "bright_blue"
    timestamp_date = "not bold default"
    timestamp_t = "dim bright_white"
    timestamp_time = "dim default"
    timestamp_z = "dim bright_white"
    asn_org = "bright_white"
    whois_org = "bright_cyan"
    tags = "bright_white on black"
    tags_green = "bright_green on black"
    tags_red = "bright_red on black"
    info = "bold green"
    warn = "bold yellow"
    error = "bold red"


def open_test_data(fname: str) -> str:
    path = Path(__file__).parent.resolve() / "test_data" / fname
    with open(path) as f:
        return f.read()


def greynoise_get(ip, pool) -> GreynoiseIp:
    """ Mock replacement for GreynoiseClient().get_ip() """
    return GreynoiseIp.model_validate(pool[ip])


def ipwhois_get(ip, pool) -> IpWhois:
    """ Mock replacement for IpWhoisClient().get_ipwhois() """
    return IpWhois.model_validate(pool[ip])


def shodan_get_ip(ip, pool) -> ShodanIp:
    """ Mock replacement for ShodanClient().get_ip() """
    return ShodanIp.model_validate(pool[ip])


def timestamp_text(ts) -> Optional[RenderableType]:
    """ Standard timestamp formatting """
    theme = TestTheme()
    return Text(
        ts,
        spans=[
            Span(10, 11, theme.timestamp_t),
            Span(11, 19, theme.timestamp_time),
            Span(19, 20, theme.timestamp_z),
        ]
    )


@pytest.fixture(scope="module")
def test_data():
    return open_test_data


@pytest.fixture(scope="module")
def theme():
    return TestTheme()


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
def display_timestamp():
    return timestamp_text
