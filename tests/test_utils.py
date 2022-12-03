import pytest

from freezegun import freeze_time
from rich.text import Text

from wtfis.utils import (
    Timestamp,
    older_than,
    smart_join,
    error_and_exit,
    refang,
    is_ip,
)


class TestUtils:
    def test_Timestamp_1(self):
        assert Timestamp(1660428690).timestamp == "2022-08-13T22:11:30Z"

    def test_Timestamp_2(self):
        assert Timestamp("2017-04-26T15:43:49.000-07:00").timestamp == "2017-04-26T22:43:49Z"

    def test_Timestamp_3(self):
        assert Timestamp(None).timestamp is None
        assert Timestamp("2017-04-26T22:43:49Z").timestamp == "2017-04-26T22:43:49Z"
        assert Timestamp("1660428690").timestamp == "2022-08-13T22:11:30Z"

    def test_Timestamp_4(self):
        assert Timestamp("2017-04-26T22:43:49.00Z").timestamp == "2017-04-26T22:43:49Z"
        assert Timestamp("2017-04-26T22:43:49+0000").timestamp == "2017-04-26T22:43:49Z"
        assert Timestamp("2017-04-26 22:43:49").timestamp == "2017-04-26 22:43:49"
        assert Timestamp("a long time ago").timestamp == "a long time ago"

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
