import pytest
from pathlib import Path

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


@pytest.fixture(scope="module")
def test_data():
    return open_test_data


@pytest.fixture(scope="module")
def mock_ipwhois_get():
    return ipwhois_get


@pytest.fixture(scope="module")
def mock_shodan_get_ip():
    return shodan_get_ip
