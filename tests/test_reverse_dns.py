import socket
import unittest
from unittest.mock import patch, MagicMock

from rich.console import Console
from rich.progress import Progress

from wtfis.clients.virustotal import VTClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.handlers.ip import IpAddressHandler


class TestReverseDNS(unittest.TestCase):
    @patch("socket.gethostbyaddr")
    def test_reverse_dns_lookup_success(self, mock_gethostbyaddr):
        # Mock successful response
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        
        # Create mock objects
        console = MagicMock(spec=Console)
        progress = MagicMock(spec=Progress)
        vt_client = MagicMock(spec=VTClient)
        ip_geoasn_client = MagicMock(spec=IpWhoisClient)
        
        # Create the handler
        handler = IpAddressHandler(
            entity="8.8.8.8",
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=vt_client,
            shodan_client=None,
            greynoise_client=None,
            abuseipdb_client=None,
            urlhaus_client=None,
        )
        
        # Call the method to test
        handler._reverse_dns_lookup()
        
        # Assert
        mock_gethostbyaddr.assert_called_once_with("8.8.8.8")
        self.assertEqual(handler.reverse_dns, "dns.google")

    @patch("socket.gethostbyaddr")
    def test_reverse_dns_lookup_failure(self, mock_gethostbyaddr):
        # Mock failure
        mock_gethostbyaddr.side_effect = socket.herror()
        
        # Create mock objects
        console = MagicMock(spec=Console)
        progress = MagicMock(spec=Progress)
        vt_client = MagicMock(spec=VTClient)
        ip_geoasn_client = MagicMock(spec=IpWhoisClient)
        
        # Create the handler
        handler = IpAddressHandler(
            entity="192.0.2.1", # RFC 5737 TEST-NET-1 address
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=vt_client,
            shodan_client=None,
            greynoise_client=None,
            abuseipdb_client=None,
            urlhaus_client=None,
        )
        
        # Call the method to test
        handler._reverse_dns_lookup()
        
        # Assert
        mock_gethostbyaddr.assert_called_once_with("192.0.2.1")
        self.assertIsNone(handler.reverse_dns)

    def test_skip_rdns_flag(self):
        # Create mock objects
        console = MagicMock(spec=Console)
        progress = MagicMock(spec=Progress)
        progress.add_task = MagicMock(return_value="task_id")
        vt_client = MagicMock(spec=VTClient)
        ip_geoasn_client = MagicMock(spec=IpWhoisClient)
        
        # Create the handler with skip_rdns=True
        handler = IpAddressHandler(
            entity="8.8.8.8",
            console=console,
            progress=progress,
            vt_client=vt_client,
            ip_geoasn_client=ip_geoasn_client,
            whois_client=vt_client,
            shodan_client=None,
            greynoise_client=None,
            abuseipdb_client=None,
            urlhaus_client=None,
            skip_rdns=True,
        )
        
        # Mock methods to prevent actual API calls
        handler._fetch_vt_ip_address = MagicMock()
        handler._fetch_geoasn = MagicMock()
        handler._fetch_whois = MagicMock()
        handler._reverse_dns_lookup = MagicMock()
        
        # Call fetch_data
        handler.fetch_data()
        
        # Verify reverse_dns_lookup was not called
        handler._reverse_dns_lookup.assert_not_called() 