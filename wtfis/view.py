from rich.columns import Columns
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Any, Callable, List, Optional

from wtfis.models.ipwhois import IpWhois
from wtfis.models.passivetotal import Whois
from wtfis.models.virustotal import (
    Domain,
    LastAnalysisStats,
    PopularityRanks,
    Resolutions,
)
from wtfis.utils import iso_date


class Theme:
    panel_title = "bright_blue"
    heading = "bold yellow"
    table_field = "bold bright_magenta"
    table_value = "none"
    inline_stat = "cyan"
    info = "bold green"
    warn = "bold yellow"
    error = "bold red"

    @classmethod
    def _get_theme_vars(cls):
        return [
            attr for attr in dir(cls)
            if not callable(getattr(cls, attr))
            and not attr.startswith("__")
        ]

    def __init__(self, nocolor: Optional[bool] = False):
        for attr in type(self)._get_theme_vars():
            value = getattr(self, attr) if not nocolor else "none"
            setattr(self, attr, value)
        self.nocolor = nocolor


class View:
    """
    Handles the look of the output
    """
    def __init__(
        self,
        whois: Whois,
        domain: Domain,
        resolutions: Resolutions,
        max_resolutions: int,
        ip_enrich: Optional[List[IpWhois]] = None,
    ) -> None:
        self.console = Console()
        self.whois = whois
        self.domain = domain
        self.resolutions = resolutions
        self.ip_enrich = ip_enrich
        self.max_resolutions = max_resolutions
        self.theme = Theme()

    def _gen_heading_text(self, heading: str) -> Text:
        return Text(heading, style=self.theme.heading, justify="center", end="\n")

    def _gen_table(self, *params) -> Table:
        """ Each param should be a tuple of (field, value) """
        # Set up table
        grid = Table.grid(expand=False, padding=(0, 1))
        grid.add_column(style=self.theme.table_field)                # Field
        grid.add_column(style=self.theme.table_value, max_width=40)  # Value

        # Populate rows
        for item in params:
            field, value = item
            if value is None:  # Skip if no value
                continue
            grid.add_row(field, value)

        return grid

    def _gen_panel(self, title: str, body: Text, heading: Optional[Text] = None) -> Panel:
        panel_title = Text(title, style=self.theme.panel_title)
        renderable = Group(heading, body) if heading else body
        return Panel(renderable, title=panel_title, expand=False)

    def _cond_style(self, item: Any, func: Callable) -> Optional[str]:
        """ Conditional style """
        return func(item) if not self.theme.nocolor else "none"

    def _gen_vt_analysis_stats(self, stats: LastAnalysisStats) -> Text:
        # Custom style
        def stats_style(malicious):
            return self.theme.error if malicious >= 1 else self.theme.info

        total = stats.harmless + stats.malicious + stats.suspicious + stats.timeout + stats.undetected
        return Text(f"{stats.malicious}/{total} malicious", style=self._cond_style(stats.malicious, stats_style))

    def _gen_vt_reputation(self, reputation: int) -> Text:
        # Custom style
        def rep_style(reputation):
            if reputation > 0:
                return self.theme.info
            elif reputation < 0:
                return self.theme.error

        return Text(str(reputation), style=self._cond_style(reputation, rep_style))

    def _gen_vt_popularity(self, popularity_ranks: PopularityRanks) -> Optional[Text]:
        if len(popularity_ranks.__root__) == 0:
            return None

        text = Text()
        for source, popularity in popularity_ranks.__root__.items():
            text.append(f"{source} (")
            text.append(str(popularity.rank), style=self.theme.inline_stat)
            text.append(")")
            if source != list(popularity_ranks.__root__.keys())[-1]:
                text.append("\n")
        return text

    def _get_ip_enrichment(self, ip: str) -> Optional[IpWhois]:
        for ipwhois in self.ip_enrich:
            if ipwhois.ip == ip:
                return ipwhois

    def whois_panel(self) -> Panel:
        heading = self._gen_heading_text(self.whois.domain)
        body = self._gen_table(
            ("Registrar:", self.whois.registrar),
            ("Organization:", self.whois.organization),
            ("Name:", self.whois.name),
            ("Email:", self.whois.contactEmail),
            ("Phone:", self.whois.registrant.telephone),
            ("Registered:", iso_date(self.whois.registered)),
            ("Updated:", iso_date(self.whois.registryUpdatedAt)),
            ("Expires:", iso_date(self.whois.expiresAt)),
        )
        return self._gen_panel("whois", body, heading)

    def domain_panel(self) -> Panel:
        attributes = self.domain.data.attributes

        # Analysis
        analysis = self._gen_vt_analysis_stats(attributes.last_analysis_stats)

        # Reputation
        reputation = self._gen_vt_reputation(attributes.reputation)

        # Popularity
        popularity = self._gen_vt_popularity(attributes.popularity_ranks)

        # Content
        heading = self._gen_heading_text(self.domain.data.id_)
        body = self._gen_table(
            ("Analysis:", analysis),
            ("Reputation:", reputation),
            ("Popularity:", popularity),
            ("Created:", iso_date(attributes.creation_date)),
            ("Updated:", iso_date(attributes.last_modification_date)),
            ("Last Update:", iso_date(attributes.last_dns_records_date)),
        )
        return self._gen_panel("virustotal", body, heading)

    def ip_panels(self) -> List[Panel]:
        panels = []
        for idx, ip in enumerate(self.resolutions.data):
            if idx == self.max_resolutions:
                break
            attributes = ip.attributes

            # Analysis
            analysis = self._gen_vt_analysis_stats(attributes.ip_address_last_analysis_stats)

            # IP Enrichment
            enrich = self._get_ip_enrichment(attributes.ip_address)

            # Content
            heading = self._gen_heading_text(attributes.ip_address)
            data = [
                ("Analysis:", analysis),
                ("Date:", iso_date(attributes.date)),
            ]
            if enrich:
                data += [
                    ("ASN:", f"{enrich.connection.asn} ({enrich.connection.org})"),
                    ("ISP:", enrich.connection.isp),
                    ("Location:", ", ".join((enrich.city, enrich.region, enrich.country_code))),
                ]
            body = self._gen_table(*data)
            panels.append(self._gen_panel("ip address", body, heading))
        return panels

    def print(self):
        renderables = [
            self.whois_panel(),
            self.domain_panel(),
        ] + self.ip_panels()
        self.console.print(Padding(Columns(renderables), (1, 0)))
