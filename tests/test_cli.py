import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.clients.virustotal import VTClient
from wtfis.config import Config, parse_args, parse_env
from wtfis.exceptions import WtfisException
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.main import generate_entity_handler, generate_view, main
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.view import DomainView, IpAddressView

POSSIBLE_ENV_VARS = [
    "VT_API_KEY",
    "IP2WHOIS_API_KEY",
    "SHODAN_API_KEY",
    "GREYNOISE_API_KEY",
    "ABUSEIPDB_API_KEY",
    "WTFIS_DEFAULTS",
]


def unset_env_vars():
    for var in POSSIBLE_ENV_VARS:
        try:
            del os.environ[var]
        except KeyError:
            pass


def fake_load_dotenv(tmp_path, fake_env_vars):
    content = [f"{k} = {v}" for k, v in fake_env_vars.items()]
    path = tmp_path / ".env.wtfis"
    path.write_text("\n".join(content))

    def fake(*_):
        load_dotenv(path)

    return fake


def simulate_progress(console):
    return Progress(
        SpinnerColumn(finished_text="[green]✓"),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


@pytest.fixture()
def fake_load_dotenv_1(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "IP2WHOIS_API_KEY": "alice",
        "SHODAN_API_KEY": "hunter2",
        "GREYNOISE_API_KEY": "upupdowndown",
        "ABUSEIPDB_API_KEY": "dummy",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_2(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "SHODAN_API_KEY": "hunter2",
        "WTFIS_DEFAULTS": "-s -1",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_3(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "WTFIS_DEFAULTS": "--no-color",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_4(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "GREYNOISE_API_KEY": "bar",
        "ABUSEIPDB_API_KEY": "dummy",
        "WTFIS_DEFAULTS": "-g -u -a",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_vt_whois(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_ip2whois(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "IP2WHOIS_API_KEY": "alice",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_all_ok(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "SHODAN_API_KEY": "hunter2",
        "GREYNOISE_API_KEY": "bar",
        "ABUSEIPDB_API_KEY": "dummy",
        "IP2WHOIS_API_KEY": "alice",
        "WTFIS_DEFAULTS": "-A",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_all_invalid(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "GREYNOISE_API_KEY": "bar",
        "WTFIS_DEFAULTS": "--all -g",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


class TestArgs:
    def test_basic(self):
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
            ],
        ):
            args = parse_args()
            assert args.entity == "www.example.com"
            assert args.max_resolutions == 3
            assert args.no_color is False
            assert args.one_column is False
            assert args.use_shodan is False
            assert args.use_greynoise is False
            assert args.use_urlhaus is False
            assert args.use_abuseipdb is False
            assert args.all is False

    def test_display(self):
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
                "-n",
                "-1",
            ],
        ):
            args = parse_args()
            assert args.no_color is True
            assert args.one_column is True

    def test_max_resolutions_ok(self):
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
                "-m",
                "8",
            ],
        ):
            args = parse_args()
            assert args.max_resolutions == 8

    def test_max_resolutions_error_1(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                    "-m",
                    "11",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert (
            capture.err
            == "usage: main [-h]\nmain: error: Maximum --max-resolutions value is 10\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_max_resolutions_error_2(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "1.1.1.1",
                    "-m",
                    "5",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == (
            "usage: main [-h]\nmain: error: --max-resolutions is not "
            "applicable to IPs\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_shodan_ok(self):
        os.environ["SHODAN_API_KEY"] = "foo"
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
                "-s",
            ],
        ):
            args = parse_args()
            assert args.use_shodan is True
        del os.environ["SHODAN_API_KEY"]

    def test_shodan_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                    "-s",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert (
            capture.err == "usage: main [-h]\nmain: error: SHODAN_API_KEY is not set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_greynoise_ok(self):
        os.environ["GREYNOISE_API_KEY"] = "foo"
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
                "-g",
            ],
        ):
            args = parse_args()
            assert args.use_greynoise is True
        del os.environ["GREYNOISE_API_KEY"]

    def test_greynoise_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                    "-g",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert (
            capture.err
            == "usage: main [-h]\nmain: error: GREYNOISE_API_KEY is not set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_urlhaus(self):
        with patch(
            "sys.argv",
            [
                "main",
                "www.example.com",
                "-u",
            ],
        ):
            args = parse_args()
            assert args.use_urlhaus is True

    def test_abuseipdb_ok(self):
        os.environ["ABUSEIPDB_API_KEY"] = "foo"
        with patch(
            "sys.argv",
            [
                "main",
                "1.1.1.1",
                "-a",
            ],
        ):
            args = parse_args()
            assert args.use_abuseipdb is True
        del os.environ["ABUSEIPDB_API_KEY"]

    def test_abuseipdb_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "1.1.1.1",
                    "-a",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert (
            capture.err
            == "usage: main [-h]\nmain: error: ABUSEIPDB_API_KEY is not set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_all_ok(self):
        os.environ["ABUSEIPDB_API_KEY"] = "foo"
        with patch(
            "sys.argv",
            [
                "main",
                "1.1.1.1",
                "-A",
            ],
        ):
            args = parse_args()
            assert args.all is True
            assert args.use_abuseipdb is False
        del os.environ["ABUSEIPDB_API_KEY"]

    def test_all_error(self, capsys):
        os.environ["SHODAN_API_KEY"] = "foo"
        with pytest.raises(SystemExit) as e:
            with patch(
                "sys.argv",
                [
                    "main",
                    "1.1.1.1",
                    "-A",
                    "-s",
                ],
            ):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == (
            "usage: main [-h]\n"
            "main: error: --use-* flags are not accepted when the --all/-A flag is set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2
        del os.environ["SHODAN_API_KEY"]


class TestEnvs:
    def test_env_file(self, fake_load_dotenv_1):
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            parse_env()
            assert os.environ["VT_API_KEY"] == "foo"
            assert os.environ["IP2WHOIS_API_KEY"] == "alice"
            assert os.environ["SHODAN_API_KEY"] == "hunter2"
            assert os.environ["GREYNOISE_API_KEY"] == "upupdowndown"
            assert os.environ["ABUSEIPDB_API_KEY"] == "dummy"
        unset_env_vars()

    @patch("wtfis.config.load_dotenv", MagicMock())
    def test_required_env_vars(self):
        os.environ["VT_API_KEY"] = "foo"
        parse_env()
        unset_env_vars()

    @patch("wtfis.config.load_dotenv", MagicMock())
    @patch("wtfis.config.Path.exists")
    def test_error(self, mock_exists, capsys):
        mock_exists.return_value = False

        with pytest.raises(SystemExit) as e:
            parse_env()

        capture = capsys.readouterr()

        assert capture.err == (
            "Error: Environment variable VT_API_KEY not set\n"
            f"Env file {Path().home() / '.env.wtfis'} was not found either. "
            "Did you forget?\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 1


class TestDefaults:
    def test_defaults_1(self, fake_load_dotenv_2):
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_2):
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                ],
            ):
                conf = Config()
                assert conf.entity == "www.example.com"
                assert conf.max_resolutions == 3
                assert conf.no_color is False
                assert conf.one_column is True
                assert conf.use_shodan is True
                assert conf.use_greynoise is False
                assert conf.use_abuseipdb is False
                assert conf.use_urlhaus is False
                assert conf.vt_api_key == "foo"
                assert conf.shodan_api_key == "hunter2"
                assert conf.abuseipdb_api_key == ""
                assert conf.greynoise_api_key == ""
                assert conf.ip2whois_api_key == ""
        unset_env_vars()

    def test_defaults_2(self, fake_load_dotenv_2):
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_2):
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                    "-s",
                ],
            ):
                conf = Config()
                assert conf.entity == "www.example.com"
                assert conf.max_resolutions == 3
                assert conf.no_color is False
                assert conf.one_column is True
                assert conf.use_shodan is False
                assert conf.use_greynoise is False
                assert conf.use_urlhaus is False
        unset_env_vars()

    def test_defaults_3(self, fake_load_dotenv_3):
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_3):
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                ],
            ):
                conf = Config()
                assert conf.entity == "www.example.com"
                assert conf.max_resolutions == 3
                assert conf.no_color is True
                assert conf.one_column is False
                assert conf.use_shodan is False
                assert conf.use_greynoise is False
                assert conf.use_urlhaus is False
        unset_env_vars()

    def test_defaults_4(self, fake_load_dotenv_4):
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_4):
            with patch(
                "sys.argv",
                [
                    "main",
                    "1.1.1.1",
                    "-u",
                ],
            ):
                conf = Config()
                assert conf.entity == "1.1.1.1"
                assert conf.no_color is False
                assert conf.one_column is False
                assert conf.use_shodan is False
                assert conf.use_greynoise is True
                assert conf.use_urlhaus is False
                assert conf.use_abuseipdb is True
                assert conf.abuseipdb_api_key == "dummy"
        unset_env_vars()


class TestAllFlag:
    def test_1_ok(self, fake_load_dotenv_1):
        """-A flag in argument"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                    "--all",
                ],
            ):
                conf = Config()
                assert conf.use_shodan is True
                assert conf.use_greynoise is True
                assert conf.use_urlhaus is True
                assert conf.use_abuseipdb is True
                assert conf.use_urlhaus is True
        unset_env_vars()

    def test_2_ok(self, fake_load_dotenv_all_ok):
        """-A flag in config file"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_all_ok):
            with patch(
                "sys.argv",
                [
                    "main",
                    "www.example.com",
                ],
            ):
                conf = Config()
                assert conf.use_shodan is True
                assert conf.use_greynoise is True
                assert conf.use_urlhaus is True
                assert conf.use_abuseipdb is True
                assert conf.use_urlhaus is True
        unset_env_vars()

    def test_3_error(self, fake_load_dotenv_1, capsys):
        """Invalid arguments"""
        with pytest.raises(SystemExit) as e:
            with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
                with patch(
                    "sys.argv",
                    [
                        "main",
                        "www.example.com",
                        "-A",
                        "-s",
                    ],
                ):
                    _ = Config()

        capture = capsys.readouterr()

        assert capture.err == (
            "usage: main [-h]\n"
            "main: error: --use-* flags are not accepted when the --all/-A flag is set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2
        unset_env_vars()

    def test_4_error(self, fake_load_dotenv_all_invalid, capsys):
        """Invalid WTFIS_DEFAULTS options"""
        with pytest.raises(SystemExit) as e:
            with patch("wtfis.config.load_dotenv", fake_load_dotenv_all_invalid):
                with patch(
                    "sys.argv",
                    [
                        "main",
                        "www.example.com",
                    ],
                ):
                    _ = Config()

        capture = capsys.readouterr()

        assert capture.err == (
            "usage: main [-h]\n"
            "main: error: --use-* flags are not accepted when the --all/-A flag is set\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 2
        unset_env_vars()


class TestGenEntityHandler:
    """Tests for the generate_entity_handler function"""

    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_1(self, fake_load_dotenv_1):
        """Domain with default params"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert isinstance(entity, DomainHandler)
        assert entity.entity == "www.example.com"
        assert entity.max_resolutions == 3
        assert entity.console == console
        assert entity.progress == progress
        assert isinstance(entity._vt, VTClient)
        assert isinstance(entity._geoasn, IpWhoisClient)
        assert isinstance(entity._whois, Ip2WhoisClient)
        assert entity._shodan is None
        assert entity._greynoise is None
        assert entity._urlhaus is None
        assert entity._abuseipdb is None
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com", "-s", "-g", "-u", "-m", "5"])
    def test_handler_domain_2(self, fake_load_dotenv_1):
        """Domain with Shodan and Greynoise and non-default max_resolutions"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert entity.max_resolutions == 5
        assert isinstance(entity._geoasn, IpWhoisClient)
        assert isinstance(entity._whois, Ip2WhoisClient)
        assert isinstance(entity._shodan, ShodanClient)
        assert isinstance(entity._greynoise, GreynoiseClient)
        assert isinstance(entity._urlhaus, UrlHausClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_3(self, fake_load_dotenv_vt_whois):
        """Domain using default Ip2Whois for whois"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_vt_whois):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert isinstance(entity._whois, VTClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_4(self, fake_load_dotenv_ip2whois):
        """Domain using default Ip2Whois for whois"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_ip2whois):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert isinstance(entity._whois, Ip2WhoisClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "1[.]1[.]1[.]1"])
    def test_handler_ip_1(self, fake_load_dotenv_1):
        """IP with default params"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert isinstance(entity, IpAddressHandler)
        assert entity.entity == "1.1.1.1"
        assert entity.console == console
        assert entity.progress == progress
        assert isinstance(entity._vt, VTClient)
        assert isinstance(entity._geoasn, IpWhoisClient)
        assert isinstance(entity._whois, VTClient)
        assert entity._greynoise is None
        assert entity._urlhaus is None
        unset_env_vars()

    @patch("sys.argv", ["main", "1[.]1[.]1[.]1", "-s", "-g", "-u", "-a"])
    def test_handler_ip_2(self, fake_load_dotenv_1):
        """IP with various options"""
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            conf = Config()
            console = Console()
            progress = (simulate_progress(console),)
            entity = generate_entity_handler(conf, console, progress)
        assert isinstance(entity._geoasn, IpWhoisClient)
        assert isinstance(entity._whois, VTClient)
        assert isinstance(entity._shodan, ShodanClient)
        assert isinstance(entity._greynoise, GreynoiseClient)
        assert isinstance(entity._urlhaus, UrlHausClient)
        assert isinstance(entity._abuseipdb, AbuseIpDbClient)
        unset_env_vars()


class TestGenView:
    """Tests for the generate_view function"""

    @patch("wtfis.main.DomainView", return_value=MagicMock(spec=DomainView))
    def test_view_domain_1(self, m_domain_view, test_data):
        """Domain view with default params"""
        entity = DomainHandler(
            entity=MagicMock(),
            console=MagicMock(),
            progress=MagicMock(),
            vt_client=MagicMock(),
            ip_geoasn_client=MagicMock(),
            whois_client=MagicMock(),
            shodan_client=MagicMock(),
            greynoise_client=MagicMock(),
            abuseipdb_client=MagicMock(),
            urlhaus_client=MagicMock(),
        )
        entity.vt_info = Domain.model_validate(
            json.loads(test_data("vt_domain_gist.json"))
        )
        entity.whois = MagicMock()
        entity.ip_enrich = MagicMock()
        view = generate_view(MagicMock(), MagicMock(), entity)
        assert isinstance(view, DomainView)

    @patch("wtfis.main.IpAddressView", return_value=MagicMock(spec=IpAddressView))
    def test_view_ip_1(self, m_ip_view, test_data):
        """IP address view with default params"""
        entity = IpAddressHandler(
            entity=MagicMock(),
            console=MagicMock(),
            progress=MagicMock(),
            vt_client=MagicMock(),
            ip_geoasn_client=MagicMock(),
            whois_client=MagicMock(),
            shodan_client=MagicMock(),
            greynoise_client=MagicMock(),
            abuseipdb_client=MagicMock(),
            urlhaus_client=MagicMock(),
        )
        entity.vt_info = IpAddress.model_validate(
            json.loads(test_data("vt_ip_1.1.1.1.json"))
        )
        entity.whois = MagicMock()
        entity.ip_enrich = MagicMock()
        view = generate_view(MagicMock(), MagicMock(), entity)
        assert isinstance(view, IpAddressView)

    def test_view_error(self):
        """IP address view with default params"""
        with pytest.raises(WtfisException):
            generate_view(MagicMock(), MagicMock(), "foobar")


class TestMain:
    @patch("sys.argv", ["main", "www.example.com"])
    @patch("wtfis.main.Console", return_value=Console())
    @patch("wtfis.main.Config")
    @patch("wtfis.main.get_progress")
    @patch("wtfis.main.generate_entity_handler", return_value=MagicMock())
    @patch("wtfis.main.generate_view", return_value=MagicMock())
    def test_main_default(
        self, m_view, m_handler, m_progress, m_conf, m_console, fake_load_dotenv_1
    ):
        """Test all calls with default values"""
        m_progress.return_value = simulate_progress(m_console())
        with patch("wtfis.config.load_dotenv", fake_load_dotenv_1):
            m_conf.return_value = Config()
            main()
        m_handler.assert_called_once_with(m_conf(), m_console(), m_progress())
        m_handler().fetch_data.assert_called_once_with()
        m_handler().print_warnings.assert_called_once_with()
        m_view.assert_called_once_with(m_conf(), m_console(), m_handler())
        m_view().print.assert_called_once_with(one_column=False)
        unset_env_vars()
