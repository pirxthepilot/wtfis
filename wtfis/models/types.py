"""
Type aliases
"""

from typing import Union

from wtfis.models.abuseipdb import AbuseIpDbMap
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ip2location import Ip2Location, Ip2LocationMap
from wtfis.models.ipinfo import IpInfo, IpInfoMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.urlhaus import UrlHausMap

# IP enrichment map types
IpEnrichmentType = Union[
    AbuseIpDbMap,
    GreynoiseIpMap,
    Ip2LocationMap,
    IpInfoMap,
    IpWhoisMap,
    ShodanIpMap,
    UrlHausMap,
]

# Domain/FQDN enrichment map types
DomainEnrichmentType = Union[UrlHausMap,]

# IP geolocation and ASN types
IpGeoAsnType = Union[
    Ip2Location,
    IpInfo,
    IpWhois,
]

IpGeoAsnMapType = Union[
    Ip2LocationMap,
    IpInfoMap,
    IpWhoisMap,
]
