import pytest

from freezegun import freeze_time
from rich.text import Text

from wtfis.utils import (
    iso_date,
    older_than,
    smart_join,
    error_and_exit,
    refang,
    is_ip,
)


class TestUtils:
    def test_iso_date_1(self):
        assert iso_date(1660428690) == "2022-08-13T22:11:30Z"

    def test_iso_date_2(self):
        assert iso_date("2017-04-26T15:43:49.000-07:00") == "2017-04-26T22:43:49Z"

    def test_iso_date_3(self):
        assert iso_date(None) is None
        assert iso_date("2017-04-26T22:43:49Z") == "2017-04-26T22:43:49Z"
        assert iso_date("1660428690") == "2022-08-13T22:11:30Z"

    def test_iso_date_4(self):
        assert iso_date("2017-04-26T22:43:49.00Z") == "2017-04-26T22:43:49Z"
        assert iso_date("2017-04-26T22:43:49+0000") == "2017-04-26T22:43:49Z"
        assert iso_date("2017-04-26 22:43:49") == "2017-04-26 22:43:49"
        assert iso_date("a long time ago") == "a long time ago"

    @freeze_time("2022-08-12")
    def test_older_than(self):
        assert older_than(1659146024, 30) is False
        assert older_than(1657418024, 30) is True

    def test_smart_join_1(self):
        output = smart_join(*["foo", "bar", "baz"])
        assert type(output) is Text
        assert str(output) == "foo, bar, baz"
        assert output == (
            Text()
            .append("foo")
            .append(", ", style="default")
            .append("bar")
            .append(", ", style="default")
            .append("baz")
        )

    def test_smart_join_2(self):
        output = smart_join(*["foo", "bar", "baz"], style="blue")
        assert type(output) is Text
        assert str(output) == "foo, bar, baz"
        assert output == (
            Text()
            .append("foo", style="blue")
            .append(", ", style="default")
            .append("bar", style="blue")
            .append(", ", style="default")
            .append("baz", style="blue")
        )

    def test_smart_join_3(self):
        output_1 = smart_join(*[])
        assert type(output_1) is str
        assert output_1 == ""

        output_2 = smart_join(None)
        assert type(output_2) is str
        assert output_2 == ""

    def test_error_and_exit(self):
        with pytest.raises(SystemExit) as e:
            error_and_exit("foo", 2)
        assert e.value.code == 2

    def test_refang(self):
        assert refang("foo[.]bar[.]com") == "foo.bar.com"

    def test_is_ip(self):
        assert is_ip("1.1.1.1") is True
        assert is_ip("foo.example.com") is False
