import pytest
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Span, Text
from unittest.mock import MagicMock

from wtfis.models.ipwhois import IpWhois
from wtfis.models.passivetotal import Whois
from wtfis.models.virustotal import (
    Domain,
    HistoricalWhois,
    Resolutions,
)
from wtfis.ui.view import View


@pytest.fixture()
def view01(test_data):
    """ gist.github.com with PT whois. Complete test of all panels. """
    return View(
        console=Console(),
        domain=Domain.parse_obj(json.loads(test_data("vt_domain_gist.json"))),
        resolutions=Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json"))),
        whois=Whois.parse_obj(json.loads(test_data("pt_whois_gist.json"))),
        ip_enrich=[IpWhois.parse_obj(o) for o in json.loads(test_data("ipwhois_gist.json"))],
    )


@pytest.fixture()
def view02(test_data):
    """
    gist.github.com VT whois. Resolution and whois tests only. Test empty enrichment
    and max_resolutions=1
    """
    return View(
        console=Console(),
        domain=MagicMock(),
        resolutions=Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json"))),
        whois=HistoricalWhois.parse_obj(json.loads(test_data("vt_whois_gist.json"))),
        ip_enrich=[],
        max_resolutions=1,
    )


@pytest.fixture()
def view03(test_data):
    """ bbc.co.uk VT whois. Whois panel test only. Test whois with no domain field. """
    return View(
        console=Console(),
        domain=MagicMock(),
        resolutions=MagicMock(),
        whois=HistoricalWhois.parse_obj(json.loads(test_data("vt_whois_bbc.json"))),
        ip_enrich=[],
    )


@pytest.fixture()
def view04(test_data):
    """
    google.com domain. Domain and resolution test only. Test domain with 1 malicious
    analysis point, and empty resolutions.
    """
    return View(
        console=Console(),
        domain=Domain.parse_obj(json.loads(test_data("vt_domain_google.json"))),
        resolutions=None,
        whois=MagicMock(),
        ip_enrich=[],
    )


@pytest.fixture()
def view05(test_data):
    """ tucows.com domain. Domain test only. Test domain with negative reputation and no popularity."""
    return View(
        console=Console(),
        domain=Domain.parse_obj(json.loads(test_data("vt_domain_tucows.json"))),
        resolutions=MagicMock(),
        whois=MagicMock(),
        ip_enrich=[],
    )


@pytest.fixture()
def view06(test_data):
    """ exmple.com VT whois. Whois test only. Test empty whois_map."""
    return View(
        console=Console(),
        domain=MagicMock(),
        resolutions=MagicMock(),
        whois=HistoricalWhois.parse_obj(json.loads(test_data("vt_whois_example_2.json"))),
        ip_enrich=[],
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
                    Span(10, 13, "cyan"),
                    Span(31, 36, "cyan"),
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
        table = group[1].renderables[0]
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
        assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

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
            "State:",
            "Country:",
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
            "CA",
            "US",
            ("dns1.p08.nsone.net, dns2.p08.nsone.net, dns3.p08.nsone.net, dns4.p08.nsone.net, ns-1283.awsdns-32.org, "
             "ns-1707.awsdns-21.co.uk, ns-421.awsdns-52.com, ns-520.awsdns-01.net"),
            "2007-10-09T18:20:50Z",
            "2020-09-08T09:18:27Z",
            "2022-10-09T07:00:00Z"
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
            "GITHUB.COM",
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
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "MarkMonitor Inc.",
            "DNS1.P08.NSONE.NET, DNS2.P08.NSONE.NET, DNS3.P08.NSONE.NET, "
            "DNS4.P08.NSONE.NET, NS-1283.AWSDNS-32.ORG, NS-1707.AWSDNS-21.CO.UK, "
            "NS-421.AWSDNS-52.COM, NS-520.AWSDNS-01.NET",
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
                    Span(10, 11, "cyan"),
                    Span(22, 23, "cyan"),
                    Span(32, 33, "cyan"),
                    Span(51, 52, "cyan"),
                    Span(65, 66, "cyan"),
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
            "2022-08-17T05:30:23Z",
            "2022-08-16T22:24:18Z",
        ]


class TestView06:
    def test_whois_panel(self, view06):
        whois = view06.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Warning message
        assert whois.renderable == Text("Unable to gather whois data")
