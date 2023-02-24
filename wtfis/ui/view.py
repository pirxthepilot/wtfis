from rich.columns import Columns
from rich.console import (
    Console,
    Group,
    RenderableType,
)
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text
from typing import List, Optional, Tuple, Union

from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.virustotal import (
    Domain,
    IpAddress,
    Resolutions,
)
from wtfis.ui.base import BaseView
from wtfis.utils import Timestamp, smart_join


class DomainView(BaseView):
    """
    Handler for FQDN and domain lookup output
    """
    def __init__(
        self,
        console: Console,
        entity: Domain,
        resolutions: Optional[Resolutions],
        whois: WhoisBase,
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap,
        max_resolutions: int = 3,
    ) -> None:
        super().__init__(console, entity, whois, ip_enrich, greynoise)
        self.resolutions = resolutions
        self.max_resolutions = max_resolutions

    def domain_panel(self) -> Panel:
        attributes = self.entity.data.attributes

        # Analysis
        analysis = self._gen_vt_analysis_stats(
            attributes.last_analysis_stats,
            self._vendors_who_flagged_malicious()
        )

        # Reputation
        reputation = self._gen_vt_reputation(attributes.reputation)

        # Popularity
        popularity = self._gen_vt_popularity(attributes.popularity_ranks)

        # Categories
        categories = (
            smart_join(*attributes.categories, style=self.theme.tags)
            if attributes.categories else None
        )

        # Content
        heading = self._gen_heading_text(
            self.entity.data.id_,
            hyperlink=f"{self.vt_gui_baseurl_domain}/{self.entity.data.id_}"
        )
        body = self._gen_table(
            ("Analysis:", analysis),
            ("Reputation:", reputation),
            ("Popularity:", popularity),
            ("Categories:", categories),
            ("Updated:", Timestamp(attributes.last_modification_date).render),
            ("Last Seen:", Timestamp(attributes.last_dns_records_date).render),
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

            # Content
            heading = self._gen_heading_text(
                attributes.ip_address,
                hyperlink=f"{self.vt_gui_baseurl_ip}/{attributes.ip_address}"
            )
            data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = [
                ("Analysis:", analysis),
                ("Resolved:", Timestamp(attributes.date).render),
            ]

            # IP Enrichment
            enrich = self._get_ip_enrichment(attributes.ip_address)

            if enrich:
                if isinstance(enrich, IpWhois):
                    # IPWhois
                    asn = self._gen_asn_text(enrich.connection.asn, enrich.connection.org)
                    data += [
                        ("ASN:", asn),
                        ("ISP:", enrich.connection.isp),
                        ("Location:", smart_join(enrich.city, enrich.region, enrich.country)),
                    ]
                else:
                    # Shodan
                    asn = self._gen_asn_text(enrich.asn, enrich.org)
                    tags = smart_join(*enrich.tags, style=self.theme.tags) if enrich.tags else None
                    services_linked = self._gen_linked_field_name(
                        "Services",
                        hyperlink=f"{self.shodan_gui_baseurl}/{attributes.ip_address}"
                    )
                    data += [
                        ("ASN:", asn),
                        ("ISP:", enrich.isp),
                        ("Location:", smart_join(enrich.city, enrich.region_name, enrich.country_name)),
                        ("OS:", enrich.os),
                        (services_linked, self._gen_shodan_services(enrich)),
                        ("Tags:", tags),
                        ("Last Scan:", Timestamp(f"{enrich.last_update}+00:00").render),  # Timestamps are UTC
                                                                                          # (source: Google)
                    ]

            # Greynoise
            greynoise = self._get_greynoise_enrichment(attributes.ip_address)

            if greynoise:
                data += [self._gen_greynoise_tuple(greynoise)]

            # Include a disclaimer if last seen is older than 1 year
            # Note: Disabled for now because I originally understood that the resolution date was the last time
            # the domain was resolved, but it may actually be he first time the IP itself was seen with the domain.
            # if enrich and older_than(attributes.date, 365):
            #     body = Group(
            #         self._gen_table(*data),
            #         Text("**Enrichment data may be inaccurate", style=self.theme.disclaimer),
            #     )  # type: Union[Group, Table, str]
            # else:
            #     body = self._gen_table(*data)

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


class IpAddressView(BaseView):
    """
    Handler for IP Address lookup output
    """
    def __init__(
        self,
        console: Console,
        entity: IpAddress,
        whois: WhoisBase,
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap,
    ) -> None:
        super().__init__(console, entity, whois, ip_enrich, greynoise)

    def ip_panel(self) -> Panel:
        attributes = self.entity.data.attributes

        # Analysis
        analysis = self._gen_vt_analysis_stats(
            attributes.last_analysis_stats,
            self._vendors_who_flagged_malicious()
        )

        # Reputation
        reputation = self._gen_vt_reputation(attributes.reputation)

        # Content
        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = [
            ("Analysis:", analysis),
            ("Reputation:", reputation),
            ("Updated:", Timestamp(attributes.last_modification_date).render),
        ]

        # IP Enrichment
        enrich = self._get_ip_enrichment(self.entity.data.id_)

        if enrich:
            if isinstance(enrich, IpWhois):
                # IPWhois
                asn = self._gen_asn_text(enrich.connection.asn, enrich.connection.org)
                data += [
                    ("ASN:", asn),
                    ("ISP:", enrich.connection.isp),
                    ("Location:", smart_join(enrich.city, enrich.region, enrich.country)),
                ]
            else:
                # Shodan
                asn = self._gen_asn_text(enrich.asn, enrich.org)
                tags = smart_join(*enrich.tags, style=self.theme.tags) if enrich.tags else None
                services_linked = self._gen_linked_field_name(
                    "Services",
                    hyperlink=f"{self.shodan_gui_baseurl}/{self.entity.data.id_}"
                )
                data += [
                    ("ASN:", asn),
                    ("ISP:", enrich.isp),
                    ("Location:", smart_join(enrich.city, enrich.region_name, enrich.country_name)),
                    ("OS:", enrich.os),
                    (services_linked, self._gen_shodan_services(enrich)),
                    ("Tags:", tags),
                    ("Last Scan:", Timestamp(f"{enrich.last_update}+00:00").render),  # Timestamps are UTC
                                                                                      # (source: Google)
                ]

        # Greynoise
        greynoise = self._get_greynoise_enrichment(self.entity.data.id_)

        if greynoise:
            data += [self._gen_greynoise_tuple(greynoise)]

        # Altogether now
        heading = self._gen_heading_text(
            self.entity.data.id_,
            hyperlink=f"{self.vt_gui_baseurl_ip}/{self.entity.data.id_}"
        )
        body = self._gen_table(*data)

        return self._gen_panel("ip", self._gen_info(body, heading))

    def print(self, one_column: bool = False) -> None:
        renderables = [i for i in (
            self.ip_panel(),
            self.whois_panel(),
        ) if i is not None]

        if one_column:
            self.console.print(Group(*([""] + renderables)))  # type: ignore
        else:
            self.console.print(Padding(Columns(renderables), (1, 0)))
