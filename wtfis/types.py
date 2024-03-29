"""
Type aliases
"""
from typing import Union

from wtfis.models.abuseipdb import AbuseIpDbMap
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.urlhaus import UrlHausMap

# IP enrichment types
IpEnrichmentType = Union[
    GreynoiseIpMap,
    IpWhoisMap,
    ShodanIpMap,
    UrlHausMap,
    AbuseIpDbMap,
]

# Domain/FQDN enrichment types
DomainEnrichmentType = UrlHausMap
