import pytest

from pyp0f.exceptions import ParsingError, FieldError
from pyp0f.utils.parse import (
    WILDCARD,
    parsing_error_wrapper,
    split_parts,
    parse_from_options,
    parse_num_in_range,
    range_num_parser,
)


def test_parsing_error_wrapper():
    with pytest.raises(ParsingError) as e:
        with parsing_error_wrapper(line_no=100):
            raise FieldError()

    assert e.value.line_no == 100


def test_split_parts():
    assert list(split_parts("1::3::5", parts=3)) == ["1", "", "3"]
    assert list(split_parts("1::3::5", parts=5)) == ["1", "", "3", "", "5"]
    assert list(split_parts("1:2", parts=2)) == ["1", "2"]
    assert list(split_parts("1:", parts=2)) == ["1", ""]


def test_parse_from_options():
    assert parse_from_options("1", {"1": 1}) == 1

    with pytest.raises(FieldError):
        parse_from_options("1", {"2": 1})

    with pytest.raises(FieldError):
        parse_from_options("3", {"1": 1})


def test_parse_num_in_range():
    assert parse_num_in_range("0", min=0, max=100) == 0
    assert parse_num_in_range("100", min=0, max=100) == 100
    assert parse_num_in_range("50", min=0, max=100) == 50

    with pytest.raises(FieldError):
        parse_num_in_range("*", min=0, max=100)

    with pytest.raises(FieldError):
        parse_num_in_range("-1", min=0, max=100)

    with pytest.raises(FieldError):
        parse_num_in_range("101", min=0, max=100)


def test_range_num_parser():
    assert range_num_parser(min=0, max=100, wildcard=True)("*") == WILDCARD
    assert range_num_parser(min=0, max=100, wildcard=True)("100") == 100

    with pytest.raises(FieldError):
        range_num_parser(min=0, max=100, wildcard=False)("*")
