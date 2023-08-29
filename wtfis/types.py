"""
Type aliases
"""
from typing import Union

from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap


# IP enrichment types
IpEnrichmentType = Union[
    GreynoiseIpMap,
    IpWhoisMap,
    ShodanIpMap,
]
