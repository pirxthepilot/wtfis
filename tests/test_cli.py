import os
import pytest
from unittest.mock import patch

from wtfis.main import parse_args


class TestArgs:
    def test_basic(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
        ]):
            args = parse_args()
            assert args.entity == "www.example.com"
            assert args.max_resolutions == 3
            assert args.no_color == False
            assert args.one_column == False
            assert args.use_shodan == False

    def test_display(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-n",
            "-1",
        ]):
            args = parse_args()
            assert args.no_color == True
            assert args.one_column == True

    def test_max_resolutions_ok(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-m",
            "8",
        ]):
            args = parse_args()
            assert args.max_resolutions == 8

    def test_max_resolutions_error_1(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "www.example.com",
                "-m",
                "11",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: Maximum --max-resolutions value is 10\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_max_resolutions_error_2(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "1.1.1.1",
                "-m",
                "5",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: --max-resolutions is not applicable to IPs\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_shodan_ok(self):
        os.environ["SHODAN_API_KEY"] = "foo"
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-s",
        ]):
            args = parse_args()
            assert args.use_shodan == True
        del os.environ["SHODAN_API_KEY"]

    def test_shodan_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "www.example.com",
                "-s",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: SHODAN_API_KEY is not set\n"
        assert e.type == SystemExit
        assert e.value.code == 2
