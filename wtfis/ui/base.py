import abc

from rich.console import (
    Console,
    Group,
    RenderableType,
    group,
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Any, Generator, List, Optional, Tuple, Union

from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.passivetotal import Whois
from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.virustotal import (
    HistoricalWhois,
    LastAnalysisStats,
    PopularityRanks,
)
from wtfis.ui.theme import Theme
from wtfis.utils import iso_date, smart_join


class BaseView(abc.ABC):
    """
    Handles the look of the output
    """
    vt_gui_baseurl_domain = "https://virustotal.com/gui/domain"
    vt_gui_baseurl_ip = "https://virustotal.com/gui/ip-address"
    pt_gui_baseurl = "https://community.riskiq.com/search"
    shodan_gui_baseurl = "https://www.shodan.io/host"

    def __init__(
        self,
        console: Console,
        entity: Any,
        whois: Union[Whois, HistoricalWhois],
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
    ) -> None:
        self.console = console
        self.entity = entity
        self.whois = whois
        self.ip_enrich = ip_enrich
        self.theme = Theme()

    def _vendors_who_flagged_malicious(self) -> List[str]:
        vendors = []
        for key, result in self.entity.data.attributes.last_analysis_results.__root__.items():
            if result.category == "malicious":
                vendors.append(key)
        return vendors

    def _gen_heading_text(self, heading: str, hyperlink: Optional[str] = None) -> Text:
        text = Text(justify="center", end="\n")
        style = f"{self.theme.heading} link {hyperlink}" if hyperlink else self.theme.heading
        return text.append(heading, style=style)

    def _gen_linked_field_name(self, name: str, hyperlink: str) -> Text:
        text = Text(style=self.theme.table_field)
        text.append(name, style=f"link {hyperlink}")
        text.append(":")
        return text

    def _gen_table(self, *params: Tuple[Union[Text, str], Union[Text, str, None]]) -> Union[Table, str]:
        """ Each param should be a tuple of (field, value) """
        # Set up table
        grid = Table.grid(expand=False, padding=(0, 1))
        grid.add_column(style=self.theme.table_field)                                 # Field
        grid.add_column(style=self.theme.table_value, max_width=38, overflow="fold")  # Value

        # Populate rows
        valid_rows = 0
        for item in params:
            field, value = item
            if value is None or str(value) == "":  # Skip if no value
                continue
            grid.add_row(field, value)
            valid_rows += 1

        # Return empty string if no rows generated
        return grid if valid_rows > 0 else ""

    @group()
    def _gen_group(self, content: List[RenderableType]) -> Generator:
        for item in content:
            yield item

    @staticmethod
    def _gen_info(body: RenderableType, heading: Optional[Text] = None) -> RenderableType:
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
            text.append(source, style=self.theme.popularity_source)
            text.append(" (")
            text.append(str(popularity.rank), style=self.theme.inline_stat)
            text.append(")")
            if source != list(popularity_ranks.__root__.keys())[-1]:
                text.append("\n")
        return text

    def _gen_shodan_services(self, ip: ShodanIp) -> Optional[Union[Text, str]]:
        if len(ip.data) == 0:
            return None

        # Styling for port/transport list
        def ports_stylized(ports: list) -> Generator:
            for port in ports:
                yield (
                    Text()
                    .append(str(port.port), style=self.theme.port)
                    .append(f"/{port.transport}", style=self.theme.transport)
                )

        # Grouped list
        grouped = ip.group_ports_by_product()

        # Return a simple port list if no identified ports
        if (
            len(list(grouped.keys())) == 1 and
            list(grouped.keys())[0] == "Other"
        ):
            return smart_join(*ports_stylized(grouped["Other"]))

        # Return grouped display of there are identified ports
        text = Text()
        for product, ports in grouped.items():
            text.append(product, style=self.theme.product)
            text.append(" (")
            text.append(smart_join(*ports_stylized(ports)))
            text.append(")")
            if product != list(grouped.keys())[-1]:
                text.append("\n")
        return text

    def _get_ip_enrichment(self, ip: str) -> Optional[Union[IpWhois, ShodanIp]]:
        return self.ip_enrich.__root__[ip] if ip in self.ip_enrich.__root__.keys() else None

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

            heading = self._gen_heading_text(attribs.whois_map.domain or attribs.whois_map.route)
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

    @abc.abstractmethod
    def print(self, one_column: bool = False) -> None:
        pass
