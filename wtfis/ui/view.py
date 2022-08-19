from rich.columns import Columns
from rich.console import (
    Console,
    Group,
    RenderableType,
    group,
)
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Generator, List, Optional, Union

from wtfis.models.ipwhois import IpWhois
from wtfis.models.passivetotal import Whois
from wtfis.models.virustotal import (
    Domain,
    HistoricalWhois,
    LastAnalysisStats,
    PopularityRanks,
    Resolutions,
)
from wtfis.ui.theme import Theme
from wtfis.utils import iso_date, older_than, smart_join


class View:
    """
    Handles the look of the output
    """
    vt_gui_baseurl_domain = "https://virustotal.com/gui/domain"
    vt_gui_baseurl_ip = "https://virustotal.com/gui/ip-address"
    pt_gui_baseurl = "https://community.riskiq.com/search"

    def __init__(
        self,
        console: Console,
        domain: Domain,
        resolutions: Optional[Resolutions],
        whois: Union[Whois, HistoricalWhois],
        ip_enrich: List[IpWhois] = [],
        max_resolutions: int = 3,
    ) -> None:
        self.console = console
        self.domain = domain
        self.resolutions = resolutions
        self.whois = whois
        self.ip_enrich = ip_enrich
        self.max_resolutions = max_resolutions
        self.theme = Theme()

    def _vendors_who_flagged_malicious(self) -> List[str]:
        vendors = []
        for key, result in self.domain.data.attributes.last_analysis_results.__root__.items():
            if result.category == "malicious":
                vendors.append(key)
        return vendors

    def _gen_heading_text(self, heading: str, hyperlink: Optional[str] = None) -> Text:
        text = Text(justify="center", end="\n")
        style = f"{self.theme.heading} link {hyperlink}" if hyperlink else self.theme.heading
        return text.append(heading, style=style)

    def _gen_table(self, *params) -> Union[Table, str]:
        """ Each param should be a tuple of (field, value) """
        # Set up table
        grid = Table.grid(expand=False, padding=(0, 1))
        grid.add_column(style=self.theme.table_field)                # Field
        grid.add_column(style=self.theme.table_value, max_width=38)  # Value

        # Populate rows
        valid_rows = 0
        for item in params:
            field, value = item
            if value is None or str(value) == "":  # Skip if no value
                continue
            grid.add_row(field, value)
            valid_rows += 1

        # Return None if no rows generated
        return grid if valid_rows > 0 else ""

    @group()
    def _gen_group(self, content: List[RenderableType]) -> Generator:
        for item in content:
            yield item

    def _gen_info(self, body: RenderableType, heading: Optional[Text] = None) -> RenderableType:
        return Group(heading, body) if heading else body

    def _gen_panel(self, title: str, renderable: RenderableType) -> Panel:
        panel_title = Text(title, style=self.theme.panel_title)
        return Panel(renderable, title=panel_title, expand=False)

    def _gen_vt_analysis_stats(
        self,
        stats: LastAnalysisStats,
        vendors: Optional[List[str]] = None
    ) -> Text:
        # Custom style
        stats_style = self.theme.error if stats.malicious >= 1 else self.theme.info

        # Total count
        total = stats.harmless + stats.malicious + stats.suspicious + stats.timeout + stats.undetected

        # Text
        text = Text(f"{stats.malicious}/{total} malicious", style=stats_style)

        # Include list of vendors that flagged malicious
        if vendors:
            text.append("\n")
            text.append(smart_join(*vendors, style=self.theme.vendor_list))

        return text

    def _gen_vt_reputation(self, reputation: int) -> Text:
        # Custom style
        def rep_style(reputation: int) -> str:
            if reputation > 0:
                return self.theme.info
            elif reputation < 0:
                return self.theme.error
            return "default"

        return Text(str(reputation), style=rep_style(reputation))

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
        return None

    def whois_panel(self) -> Optional[Panel]:
        # Using PT Whois
        if isinstance(self.whois, Whois):
            heading = self._gen_heading_text(
                self.whois.domain,
                hyperlink=f"{self.pt_gui_baseurl}/{self.whois.domain}/whois"
            )
            body = self._gen_table(
                ("Registrar:", self.whois.registrar),
                ("Organization:", self.whois.organization),
                ("Name:", self.whois.name),
                ("Email:", self.whois.contactEmail),
                ("Phone:", self.whois.registrant.telephone),
                ("Street:", self.whois.registrant.street),
                ("City:", self.whois.registrant.city),
                ("State:", self.whois.registrant.state),
                ("Country:", self.whois.registrant.country),
                ("Nameservers:", smart_join(*self.whois.nameServers, style=self.theme.nameserver_list)),
                ("Registered:", iso_date(self.whois.registered)),
                ("Updated:", iso_date(self.whois.registryUpdatedAt)),
                ("Expires:", iso_date(self.whois.expiresAt)),
            )
        # Using VT HistoricalWhois
        else:
            if not self.whois.data:
                return None

            # Use the first, i.e. latest whois entry
            attribs = self.whois.data[0].attributes

            # Check for empty whois map
            if not attribs.whois_map:
                return self._gen_panel("whois", Text("Unable to gather whois data", style=self.theme.disclaimer))

            # Admin location
            admin_location = smart_join(
                attribs.whois_map.admin_city,
                attribs.whois_map.admin_state,
                attribs.whois_map.admin_country,
            )

            # Name servers
            name_servers = attribs.whois_map.name_servers if attribs.whois_map.name_servers else []

            heading = self._gen_heading_text(attribs.whois_map.domain)
            body = self._gen_table(
                ("Registrar:", attribs.whois_map.registrar),
                ("Organization:", attribs.whois_map.registrant_org),
                ("Name:", attribs.whois_map.registrant_name),
                ("Email:", attribs.whois_map.registrant_email),
                ("Country:", attribs.registrant_country),
                ("Admin Location:", admin_location),
                ("Nameservers:", smart_join(*name_servers, style=self.theme.nameserver_list)),
                ("Registered:", attribs.whois_map.creation_date or attribs.whois_map.registered_on),
                ("Updated:", attribs.whois_map.updated_date or attribs.whois_map.last_updated),
                ("Expires:", attribs.whois_map.expiry_date or attribs.whois_map.expiry_date_alt),
            )

        # Return None if body is empty
        return self._gen_panel("whois", self._gen_info(body, heading)) if body else None

    def domain_panel(self) -> Panel:
        attributes = self.domain.data.attributes

        # Analysis
        analysis = self._gen_vt_analysis_stats(
            attributes.last_analysis_stats,
            self._vendors_who_flagged_malicious()
        )

        # Reputation
        reputation = self._gen_vt_reputation(attributes.reputation)

        # Popularity
        popularity = self._gen_vt_popularity(attributes.popularity_ranks)

        # Content
        heading = self._gen_heading_text(
            self.domain.data.id_,
            hyperlink=f"{self.vt_gui_baseurl_domain}/{self.domain.data.id_}"
        )
        body = self._gen_table(
            ("Analysis:", analysis),
            ("Reputation:", reputation),
            ("Popularity:", popularity),
            ("Last Modified:", iso_date(attributes.last_modification_date)),
            ("Last Seen:", iso_date(attributes.last_dns_records_date)),
        )
        return self._gen_panel("virustotal", self._gen_info(body, heading))

    def resolutions_panel(self) -> Optional[Panel]:
        # Skip if no resolutions data
        if not self.resolutions:
            return None

        content = []
        for idx, ip in enumerate(self.resolutions.data):
            if idx == self.max_resolutions:
                break
            attributes = ip.attributes

            # Analysis
            analysis = self._gen_vt_analysis_stats(attributes.ip_address_last_analysis_stats)

            # IP Enrichment
            enrich = self._get_ip_enrichment(attributes.ip_address)

            # Content
            heading = self._gen_heading_text(
                attributes.ip_address,
                hyperlink=f"{self.vt_gui_baseurl_ip}/{attributes.ip_address}"
            )
            data = [
                ("Analysis:", analysis),
                ("Resolved:", iso_date(attributes.date)),
            ]
            if enrich:
                data += [
                    ("ASN:", f"{enrich.connection.asn} ({enrich.connection.org})"),
                    ("ISP:", enrich.connection.isp),
                    ("Location:", smart_join(enrich.city, enrich.region, enrich.country)),
                ]

            # Include a disclaimer if last seen is older than 1 year
            if older_than(attributes.date, 365):
                body = Group(
                    self._gen_table(*data),
                    Text("**Enrichment data may be inaccurate", style=self.theme.disclaimer),
                )  # type: Union[Group, Table, str]
            else:
                body = self._gen_table(*data)

            content.append(self._gen_info(body, heading))

            # Add extra line break if not last item in list
            if (
                idx < self.max_resolutions - 1 and
                idx < len(self.resolutions.data) - 1
            ):
                content.append("")

        # Info about how many more IPs were not shown
        if self.max_resolutions < self.resolutions.meta.count:
            content.append(
                Text(
                    f"\n+{self.resolutions.meta.count - self.max_resolutions} more",
                    justify="center",
                    style=self.theme.footer,
                )
            )

        # Render results, if existent
        if content:
            return self._gen_panel("resolutions", self._gen_group(content))

        # No result
        return None

    def print(self, one_column: bool = False) -> None:
        renderables = [i for i in (
            self.domain_panel(),
            self.resolutions_panel(),
            self.whois_panel(),
        ) if i is not None]

        if one_column:
            self.console.print(Group(*([""] + renderables)))  # type: ignore
        else:
            self.console.print(Padding(Columns(renderables), (1, 0)))
