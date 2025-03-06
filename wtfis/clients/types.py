"""
Type aliases
"""

from typing import Union

from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.virustotal import VTClient

# IP geolocation and ASN client types
IpGeoAsnClientType = Union[IpWhoisClient,]

# IP whois client types
IpWhoisClientType = Union[
    Ip2WhoisClient,
    VTClient,
]
