"""
Type aliases
"""

from typing import Union

from wtfis.models.abuseipdb import AbuseIpDbMap
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.urlhaus import UrlHausMap

# IP enrichment map types
IpEnrichmentType = Union[
    AbuseIpDbMap,
    GreynoiseIpMap,
    IpWhoisMap,
    ShodanIpMap,
    UrlHausMap,
]

# Domain/FQDN enrichment map types
DomainEnrichmentType = Union[UrlHausMap,]

# IP geolocation and ASN types
IpGeoAsnType = Union[IpWhois,]

IpGeoAsnMapType = Union[IpWhoisMap,]
