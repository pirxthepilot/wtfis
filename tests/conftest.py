import pytest
from pathlib import Path
from typing import Optional

from rich.console import RenderableType
from rich.text import Span, Text

from wtfis.models.ipwhois import IpWhois
from wtfis.models.shodan import ShodanIp


def open_test_data(fname: str) -> str:
    path = Path(__file__).parent.resolve() / "test_data" / fname
    with open(path) as f:
        return f.read()


def ipwhois_get(ip, pool) -> IpWhois:
    """ Mock replacement for IpWhoisClient().get_ipwhois() """
    return IpWhois.parse_obj(pool[ip])


def shodan_get_ip(ip, pool) -> ShodanIp:
    """ Mock replacement for ShodanClient().get_ip() """
    return ShodanIp.parse_obj(pool[ip])


def timestamp_text(ts) -> Optional[RenderableType]:
    """ Standard timestamp formatting """
    return Text(
        ts,
        spans=[
            Span(10, 11, "dim bright_white"),
            Span(11, 19, "dim default"),
            Span(19, 20, "dim bright_white"),
        ]
    )


@pytest.fixture(scope="module")
def test_data():
    return open_test_data


@pytest.fixture(scope="module")
def mock_ipwhois_get():
    return ipwhois_get


@pytest.fixture(scope="module")
def mock_shodan_get_ip():
    return shodan_get_ip


@pytest.fixture(scope="module")
def display_timestamp():
    return timestamp_text
