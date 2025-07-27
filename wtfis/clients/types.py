"""
Type aliases
"""

from typing import Union

from wtfis.clients.ip2location import Ip2LocationClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipinfo import IpInfoClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.virustotal import VTClient

# IP geolocation and ASN client types
IpGeoAsnClientType = Union[
    Ip2LocationClient,
    IpInfoClient,
    IpWhoisClient,
]

# IP whois client types
IpWhoisClientType = Union[
    Ip2WhoisClient,
    VTClient,
]
