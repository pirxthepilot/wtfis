import pytest
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Span, Text
from unittest.mock import MagicMock

from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.passivetotal import Whois as PTWhois
from wtfis.models.virustotal import (
    Domain,
    Resolutions,
    Whois as VTWhois,
)
from wtfis.models.whoisjson import Whois as WJWhois
from wtfis.ui.view import DomainView


@pytest.fixture()
def view01(test_data, mock_ipwhois_get):
    """ gist.github.com with PT whois. Complete test of all panels. """
    resolutions = Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json")))

    ipwhois_pool = json.loads(test_data("ipwhois_gist.json"))
    ipwhois_client = IpWhoisClient()
    ipwhois_client.get_ipwhois = MagicMock(side_effect=lambda ip: mock_ipwhois_get(ip, ipwhois_pool))
    ip_enrich = ipwhois_client.bulk_get_ipwhois(resolutions, 3)

    return DomainView(
        console=Console(),
        entity=Domain.parse_obj(json.loads(test_data("vt_domain_gist.json"))),
        resolutions=resolutions,
        whois=PTWhois.parse_obj(json.loads(test_data("pt_whois_gist.json"))),
        ip_enrich=ip_enrich,
    )


@pytest.fixture()
def view02(test_data):
    """
    gist.github.com VT whois. Resolution and whois tests only. Test empty enrichment
    and max_resolutions=1
    """
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json"))),
        whois=VTWhois.parse_obj(json.loads(test_data("vt_whois_gist.json"))),
        ip_enrich=IpWhoisMap(__root__={}),
        max_resolutions=1,
    )


@pytest.fixture()
def view03(test_data):
    """ bbc.co.uk VT whois. Whois panel test only. Test whois with no domain field. """
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        whois=VTWhois.parse_obj(json.loads(test_data("vt_whois_bbc.json"))),
        ip_enrich=MagicMock(),
    )


@pytest.fixture()
def view04(test_data):
    """
    google.com domain. Domain and resolution test only. Test domain with 1 malicious
    analysis point, and empty resolutions.
    """
    return DomainView(
        console=Console(),
        entity=Domain.parse_obj(json.loads(test_data("vt_domain_google.json"))),
        resolutions=None,
        whois=MagicMock(),
        ip_enrich=MagicMock(),
    )


@pytest.fixture()
def view05(test_data):
    """ tucows.com domain. Domain test only. Test domain with negative reputation and no popularity."""
    return DomainView(
        console=Console(),
        entity=Domain.parse_obj(json.loads(test_data("vt_domain_tucows.json"))),
        resolutions=MagicMock(),
        whois=MagicMock(),
        ip_enrich=MagicMock(),
    )


@pytest.fixture()
def view06(test_data):
    """ exmple.com VT whois. Whois test only. Test empty whois_map."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        whois=VTWhois.parse_obj(json.loads(test_data("vt_whois_example_2.json"))),
        ip_enrich=MagicMock(),
    )


@pytest.fixture()
def view07(test_data, mock_shodan_get_ip):
    """ gist.github.com with Shodan. Only test resolution and IP enrich. """
    resolutions = Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json")))

    shodan_pool = json.loads(test_data("shodan_gist.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client.get_ip = MagicMock(side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool))
    ip_enrich = shodan_client.bulk_get_ip(resolutions, 3)

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        whois=MagicMock(),
        ip_enrich=ip_enrich,
    )


@pytest.fixture()
def view08(test_data, mock_shodan_get_ip):
    """ www.wired.com with Shodan. Only test resolution and IP enrich. """
    resolutions = Resolutions.parse_obj(json.loads(test_data("vt_resolutions_wired.json")))

    shodan_pool = json.loads(test_data("shodan_wired.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client.get_ip = MagicMock(side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool))
    ip_enrich = shodan_client.bulk_get_ip(resolutions, 1)

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        whois=MagicMock(),
        ip_enrich=ip_enrich,
        max_resolutions=1,
    )


@pytest.fixture()
def view09(test_data, mock_shodan_get_ip):
    """ one.one.one.one with Shodan. Only test resolution and IP enrich. """
    resolutions = Resolutions.parse_obj(json.loads(test_data("vt_resolutions_one.json")))

    shodan_pool = json.loads(test_data("shodan_one.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client.get_ip = MagicMock(side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool))
    ip_enrich = shodan_client.bulk_get_ip(resolutions, 1)

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        whois=MagicMock(),
        ip_enrich=ip_enrich,
        max_resolutions=1,
    )


@pytest.fixture()
def view10(test_data):
    """ gist.github.com WhoisJSON whois. Whois panel test only. """
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        whois=WJWhois.parse_obj(json.loads(test_data("whoisjson_whois_gist.json"))),
        ip_enrich=MagicMock(),
    )


class TestView01:
    def test_domain_panel(self, view01):
        domain = view01.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("virustotal")

        # Heading
        assert domain.renderable.renderables[0] == Text(
            "gist.github.com",
            spans=[Span(0, 15, 'bold yellow link https://virustotal.com/gui/domain/gist.github.com')]
        )

        # Table
        table = domain.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Popularity:",
            "Categories:",
            "Last Modified:",
            "Last Seen:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious"),
            Text("0"),
            Text(
                "Majestic (532)\nCisco Umbrella (39463)",
                spans=[
                    Span(0, 8, "bright_cyan"),
                    Span(10, 13, "cyan"),
                    Span(15, 29, "bright_cyan"),
                    Span(31, 36, "cyan"),
                ]
            ),
            Text(
                "advice, file sharing/storage, information technology, media sharing, social networks",
                spans=[
                    Span(0, 6, "bright_white on black"),
                    Span(6, 8, "default"),
                    Span(8, 28, "bright_white on black"),
                    Span(28, 30, "default"),
                    Span(30, 52, "bright_white on black"),
                    Span(52, 54, "default"),
                    Span(54, 67, "bright_white on black"),
                    Span(67, 69, "default"),
                    Span(69, 84, "bright_white on black"),
                ]
            ),
            "2022-08-16T06:14:59Z",
            "2022-08-15T22:25:30Z",
        ]

    def test_resolutions_panel(self, view01):
        res = view01.resolutions_panel()
        assert type(res) is Panel

        # Entry 1
        group = res.renderable.renderables[0].renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, "bold yellow link https://virustotal.com/gui/ip-address/13.234.210.38")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious"),
            "2022-08-06T14:56:20Z",
            "16509 (Amazon Data Services India)",
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[
                    Span(6, 8, "default"),
                    Span(19, 21, "default"),
                ]
            )
        ]

        # Spacing
        assert res.renderable.renderables[1] == ""

        # Entry 2
        group = res.renderable.renderables[2].renderables

        # Heading
        assert group[0] == Text(
            "192.30.255.113",
            spans=[Span(0, 14, "bold yellow link https://virustotal.com/gui/ip-address/192.30.255.113")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("1/94 malicious"),
            "2022-06-21T18:10:54Z",
            "36459 (GitHub, Inc.)",
            "GitHub, Inc.",
            Text(
                "Seattle, Washington, United States",
                spans=[
                    Span(7, 9, "default"),
                    Span(19, 21, "default"),
                ]
            )
        ]

        # Spacing
        assert res.renderable.renderables[3] == ""

        # Entry 3 (NOTE: Timestamp on data modified to be really old)
        group = res.renderable.renderables[4].renderables

        # Heading
        assert group[0] == Text(
            "13.234.176.102",
            spans=[Span(0, 14, "bold yellow link https://virustotal.com/gui/ip-address/13.234.176.102")],
        )

        # Unlike the previous entries, the table is inside a group of (Table, Text) due to
        # old timestamp warning
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious"),
            "2015-08-17T07:11:53Z",
            "16509 (Amazon Data Services India)",
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[
                    Span(6, 8, "default"),
                    Span(19, 21, "default"),
                ]
            )
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing and remaining count
        assert res.renderable.renderables[5] == Text("\n+34 more")

    def test_whois_panel(self, view01):
        whois = view01.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Heading
        assert whois.renderable.renderables[0] == Text(
            "github.com",
            spans=[Span(0, 10, 'bold yellow link https://community.riskiq.com/search/github.com/whois')]
        )

        # Table
        table = whois.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Name:",
            "Email:",
            "Phone:",
            "Street:",
            "City:",
            "State:",
            "Country:",
            "Postcode:",
            "Nameservers:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "MarkMonitor Inc.",
            "GitHub, Inc.",
            "N/A",
            "abusecomplaints@markmonitor.com",
            "+1.5555555",
            "742 Evergreen Terrace",
            "Gotham",
            "CA",
            "US",
            "00000",
            ("dns1.p08.nsone.net, dns2.p08.nsone.net, dns3.p08.nsone.net, dns4.p08.nsone.net, ns-1283.awsdns-32.org, "
             "ns-1707.awsdns-21.co.uk, ns-421.awsdns-52.com, ns-520.awsdns-01.net"),
            "2007-10-09T18:20:50Z",
            "2020-09-08T09:18:27Z",
            "2022-10-09T07:00:00Z",
        ]


class TestView02:
    def test_resolutions_panel(self, view02):
        res = view02.resolutions_panel()
        assert type(res) is Panel

        # Entry 1
        group = res.renderable.renderables[0].renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, "bold yellow link https://virustotal.com/gui/ip-address/13.234.210.38")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious"),
            "2022-08-06T14:56:20Z",
        ]

        # Spacing and remaining count
        assert res.renderable.renderables[1] == Text("\n+36 more")

    def test_whois_panel(self, view02):
        whois = view02.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Heading
        assert whois.renderable.renderables[0] == Text(
            "github.com",
            spans=[Span(0, 10, 'bold yellow')]
        )

        # Table
        table = whois.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "MarkMonitor Inc.",
            "dns1.p08.nsone.net, dns2.p08.nsone.net, dns3.p08.nsone.net, "
            "dns4.p08.nsone.net, ns-1283.awsdns-32.org, ns-1707.awsdns-21.co.uk, "
            "ns-421.awsdns-52.com, ns-520.awsdns-01.net",
            "unsigned",
            "2007-10-09T18:20:50Z",
            "2020-09-08T09:18:27Z",
            "2022-10-09T18:20:50Z",
        ]


class TestView03:
    def test_whois_panel(self, view03):
        whois = view03.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # No Heading!

        # Table
        table = whois.renderable
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Nameservers:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "dns1.bbc.com",
            "before Aug-1996",
            "10-Dec-2020",
            "13-Dec-2025",
        ]


class TestView04:
    def test_domain_panel(self, view04):
        domain = view04.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("virustotal")

        # Heading
        assert domain.renderable.renderables[0] == Text(
            "google.com",
            spans=[Span(0, 10, 'bold yellow link https://virustotal.com/gui/domain/google.com')]
        )

        # Table
        table = domain.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Popularity:",
            "Categories:",
            "Last Modified:",
            "Last Seen:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "1/94 malicious\nCyble",
                spans=[
                    Span(15, 20, ""),
                    Span(15, 20, "cyan"),
                ]
            ),
            Text("448"),
            Text(
                "Majestic (1)\nStatvoo (1)\nAlexa (1)\nCisco Umbrella (2)\nQuantcast (1)",
                spans=[
                    Span(0, 8, "bright_cyan"),
                    Span(10, 11, "cyan"),
                    Span(13, 20, "bright_cyan"),
                    Span(22, 23, "cyan"),
                    Span(25, 30, "bright_cyan"),
                    Span(32, 33, "cyan"),
                    Span(35, 49, "bright_cyan"),
                    Span(51, 52, "cyan"),
                    Span(54, 63, "bright_cyan"),
                    Span(65, 66, "cyan"),
                ]
            ),
            Text(
                "mobile communications, portals, search engines, search engines and portals, searchengines",
                spans=[
                    Span(0, 21, "bright_white on black"),
                    Span(21, 23, "default"),
                    Span(23, 30, "bright_white on black"),
                    Span(30, 32, "default"),
                    Span(32, 46, "bright_white on black"),
                    Span(46, 48, "default"),
                    Span(48, 74, "bright_white on black"),
                    Span(74, 76, "default"),
                    Span(76, 89, "bright_white on black"),
                ]
            ),
            "2022-08-17T06:03:03Z",
            "2022-08-17T00:35:19Z",
        ]

    def test_resolutions_panel(self, view04):
        res = view04.resolutions_panel()
        assert res is None


class TestView05:
    def test_domain_panel(self, view05):
        domain = view05.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("virustotal")

        # Heading
        assert domain.renderable.renderables[0] == Text(
            "tucows.com",
            spans=[Span(0, 10, 'bold yellow link https://virustotal.com/gui/domain/tucows.com')]
        )

        # Table
        table = domain.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Categories:",
            "Last Modified:",
            "Last Seen:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "1/94 malicious\nDr.Web",
                spans=[
                    Span(15, 21, ""),
                    Span(15, 21, "cyan"),
                ]
            ),
            Text("-1"),
            Text(
                (
                    "ads/analytics, dynamic dns and isp sites, hosting, information technology, "
                    "known infection source, mobile communications, not recommended site"
                ),
                spans=[
                    Span(0, 13, "bright_white on black"),
                    Span(13, 15, "default"),
                    Span(15, 40, "bright_white on black"),
                    Span(40, 42, "default"),
                    Span(42, 49, "bright_white on black"),
                    Span(49, 51, "default"),
                    Span(51, 73, "bright_white on black"),
                    Span(73, 75, "default"),
                    Span(75, 97, "bright_white on black"),
                    Span(97, 99, "default"),
                    Span(99, 120, "bright_white on black"),
                    Span(120, 122, "default"),
                    Span(122, 142, "bright_white on black"),
                ]
            ),
            "2022-08-17T05:30:23Z",
            "2022-08-16T22:24:18Z",
        ]


class TestView06:
    def test_whois_panel(self, view06):
        whois = view06.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Warning message
        assert whois.renderable == Text("No whois data found")


class TestView07:
    def test_resolutions_panel(self, view07):
        res = view07.resolutions_panel()
        assert type(res) is Panel

        # Entry 1
        group = res.renderable.renderables[0].renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, "bold yellow link https://virustotal.com/gui/ip-address/13.234.210.38")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/13.234.210.38")]
            ),
            "Tags:",
            "Last Scan:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious"),
            "2022-08-06T14:56:20Z",
            "16509 (Amazon Data Services India)",
            "Amazon.com, Inc.",
            Text(
                "Mumbai, India",
                spans=[
                    Span(6, 8, "default"),
                ]
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 6, ""),
                    Span(0, 2, "bright_cyan"),
                    Span(2, 6, "cyan"),
                    Span(6, 8, "default"),
                    Span(8, 14, ""),
                    Span(8, 10, "bright_cyan"),
                    Span(10, 14, "cyan"),
                    Span(14, 16, "default"),
                    Span(16, 23, ""),
                    Span(16, 19, "bright_cyan"),
                    Span(19, 23, "cyan"),
                ]
            ),
            Text(
                "cloud",
                spans=[
                    Span(0, 5, 'bright_white on black')
                ]
            ),
            "2022-08-21T07:21:05Z"
        ]

        # Spacing
        assert res.renderable.renderables[1] == ""

        # Entry 2
        group = res.renderable.renderables[2].renderables

        # Heading
        assert group[0] == Text(
            "192.30.255.113",
            spans=[Span(0, 14, "bold yellow link https://virustotal.com/gui/ip-address/192.30.255.113")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/192.30.255.113")]
            ),
            "Last Scan:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("1/94 malicious"),
            "2022-06-21T18:10:54Z",
            "36459 (GitHub, Inc.)",
            "GitHub, Inc.",
            Text(
                "Seattle, United States",
                spans=[
                    Span(7, 9, "default"),
                ]
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 6, ""),
                    Span(0, 2, "bright_cyan"),
                    Span(2, 6, "cyan"),
                    Span(6, 8, "default"),
                    Span(8, 14, ""),
                    Span(8, 10, "bright_cyan"),
                    Span(10, 14, "cyan"),
                    Span(14, 16, "default"),
                    Span(16, 23, ""),
                    Span(16, 19, "bright_cyan"),
                    Span(19, 23, "cyan")
                ]
            ),
            "2022-08-21T22:33:53Z"
        ]

        # Spacing
        assert res.renderable.renderables[3] == ""

        # Entry 3 (NOTE: Timestamp on data modified to be really old)
        group = res.renderable.renderables[4].renderables

        # Heading
        assert group[0] == Text(
            "13.234.176.102",
            spans=[Span(0, 14, "bold yellow link https://virustotal.com/gui/ip-address/13.234.176.102")],
        )

        # Unlike the previous entries, the table is inside a group of (Table, Text) due to
        # old timestamp warning
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/13.234.176.102")]
            ),
            "Tags:",
            "Last Scan:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious"),
            "2015-08-17T07:11:53Z",
            "16509 (Amazon Data Services India)",
            "Amazon.com, Inc.",
            Text(
                "Mumbai, India",
                spans=[
                    Span(6, 8, "default"),
                ]
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 6, ""),
                    Span(0, 2, "bright_cyan"),
                    Span(2, 6, "cyan"),
                    Span(6, 8, "default"),
                    Span(8, 14, ""),
                    Span(8, 10, "bright_cyan"),
                    Span(10, 14, "cyan"),
                    Span(14, 16, "default"),
                    Span(16, 23, ""),
                    Span(16, 19, "bright_cyan"),
                    Span(19, 23, "cyan"),
                ]
            ),
            Text(
                "cloud",
                spans=[
                    Span(0, 5, 'bright_white on black')
                ]
            ),
            "2022-08-21T02:13:35Z"
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing and remaining count
        assert res.renderable.renderables[5] == Text("\n+34 more")


class TestView08:
    def test_resolutions_panel(self, view08):
        res = view08.resolutions_panel()
        assert type(res) is Panel

        # Entry 1
        group = res.renderable.renderables[0].renderables

        # Heading
        assert group[0] == Text(
            "199.232.34.194",
            spans=[Span(0, 14, "bold yellow link https://virustotal.com/gui/ip-address/199.232.34.194")],
        )

        # Table
        assert group[1].columns[0].style == "bold bright_magenta"
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/199.232.34.194")]
            ),
            "Tags:",
            "Last Scan:",
        ]
        assert group[1].columns[1].style == "none"
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/93 malicious"),
            "2022-06-03T22:32:19Z",
            "54113 (Fastly, Inc.)",
            "Fastly, Inc.",
            Text(
                "Atlanta, United States",
                spans=[
                    Span(7, 9, "default"),
                ]
            ),
            Text(
                "Varnish HTTP Cache (80/tcp)\nOther (443/tcp)",
                spans=[
                    Span(0, 18, "orange_red1"),
                    Span(20, 26, ""),
                    Span(20, 26, ""),
                    Span(20, 22, "bright_cyan"),
                    Span(22, 26, "cyan"),
                    Span(28, 33, "orange_red1"),
                    Span(35, 42, ""),
                    Span(35, 42, ""),
                    Span(35, 38, "bright_cyan"),
                    Span(38, 42, "cyan"),
                ]
            ),
            Text(
                "cdn",
                spans=[
                    Span(0, 3, 'bright_white on black'),
                ]
            ),
            "2022-08-21T01:33:13Z"
        ]

        # Spacing
        assert res.renderable.renderables[1] == Text("\n+199 more")


class TestView09:
    def test_resolutions_panel(self, view09):
        res = view09.resolutions_panel()
        assert type(res) is Panel

        # Entry 1
        group = res.renderable.renderables[0].renderables

        # Heading
        assert group[0] == Text(
            "1.0.0.1",
            spans=[Span(0, 7, "bold yellow link https://virustotal.com/gui/ip-address/1.0.0.1")],
        )

        # Table
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/1.0.0.1")]
            ),
            "Last Scan:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("2/94 malicious"),
            "2020-08-01T22:07:20Z",
            "13335 (APNIC and Cloudflare DNS Resolver project)",
            "Cloudflare, Inc.",
            Text(
                "Los Angeles, United States",
                spans=[
                    Span(11, 13, "default"),
                ]
            ),
            Text(
                (
                    "CloudFlare (80/tcp, 8080/tcp)\nOther (53/tcp, 53/udp, 443/tcp, 2082/tcp, "
                    "2086/tcp, 2087/tcp, 8443/tcp)"
                ),
                spans=[
                    Span(0, 10, "orange_red1"),
                    Span(12, 28, ""),
                    Span(12, 18, ""),
                    Span(12, 14, "bright_cyan"),
                    Span(14, 18, "cyan"),
                    Span(18, 20, "default"),
                    Span(20, 28, ""),
                    Span(20, 24, "bright_cyan"),
                    Span(24, 28, "cyan"),
                    Span(30, 35, "orange_red1"),
                    Span(37, 100, ""),
                    Span(37, 43, ""),
                    Span(37, 39, "bright_cyan"),
                    Span(39, 43, "cyan"),
                    Span(43, 45, "default"),
                    Span(45, 51, ""),
                    Span(45, 47, "bright_cyan"),
                    Span(47, 51, "cyan"),
                    Span(51, 53, "default"),
                    Span(53, 60, ""),
                    Span(53, 56, "bright_cyan"),
                    Span(56, 60, "cyan"),
                    Span(60, 62, "default"),
                    Span(62, 70, ""),
                    Span(62, 66, "bright_cyan"),
                    Span(66, 70, "cyan"),
                    Span(70, 72, "default"),
                    Span(72, 80, ""),
                    Span(72, 76, "bright_cyan"),
                    Span(76, 80, "cyan"),
                    Span(80, 82, "default"),
                    Span(82, 90, ""),
                    Span(82, 86, "bright_cyan"),
                    Span(86, 90, "cyan"),
                    Span(90, 92, "default"),
                    Span(92, 100, ""),
                    Span(92, 96, "bright_cyan"),
                    Span(96, 100, "cyan"),
                ]
            ),
            "2022-08-22T02:35:34Z"
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing
        assert res.renderable.renderables[1] == Text("\n+1 more")


class TestView10:
    def test_whois_panel(self, view10):
        whois = view10.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Heading
        assert whois.renderable.renderables[0] == Text(
            "github.com",
            spans=[Span(0, 10, 'bold yellow')]
        )

        # Table
        table = whois.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Email:",
            "State:",
            "Country:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "MarkMonitor, Inc.",
            "GitHub, Inc.",
            "Select Request Email Form at "
            "https://domains.markmonitor.com/whois/github.com",
            "CA",
            "US",
            "ns-1707.awsdns-21.co.uk, dns2.p08.nsone.net, dns3.p08.nsone.net, "
            "ns-421.awsdns-52.com, ns-1283.awsdns-32.org, ns-520.awsdns-01.net, "
            "dns4.p08.nsone.net, dns1.p08.nsone.net",
            "unsigned",
            "2007-10-10T01:20:50Z",
            "2022-09-07T16:10:44Z",
            "2024-10-10T01:20:50Z",
        ]
