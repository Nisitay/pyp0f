import contextlib
from typing import TypeVar, Callable, Generator, Dict

from pyp0f.exceptions import FieldError, ParsingError

T = TypeVar("T")

WILDCARD = -1  # Wildcard for numeric fields


@contextlib.contextmanager
def parsing_error_wrapper(line_no: int):
    """
    Wrap ``FieldError`` exceptions and re-raise ``ParsingError``.
    """
    try:
        yield
    except FieldError as e:
        raise ParsingError(str(e), line_no) from e


def split_parts(s: str, parts: int, sep: str = ":") -> Generator[str, None, None]:
    """
    Split a string into a number of expected parts.
    If the number of expected parts is bigger than the number of
    parts found, return an empty string for the remaining.

    Args:
        s: string to parse
        parts: Expected number of parts to return
        sep: Seperator to split with. Defaults to ":"

    Yields:
        Parsed part
    """
    for part in s.split(sep, maxsplit=parts):
        if parts:
            yield part
        parts -= 1

    for _ in range(parts):
        yield ""


def parse_from_options(field: str, options: Dict[str, T]) -> T:
    """
    Parse a field value from a fixed set of options.

    Args:
        field: Field value to parse
        options: Parsing options

    Raises:
        FieldError: Invalid field value

    Returns:
        Parsed value
    """
    if field not in options:
        raise FieldError(
            f"Can't parse an invalid field value: {field!r}. "
            f"Valid field values: {', '.join(repr(key) for key in options.keys())}"
        )
    return options[field]


def parse_num_in_range(field: str, min: int, max: int) -> int:
    """
    Parse a numeric field value and verify it is in a specified range.

    Args:
        field: Field value to parse
        min: Minimum value (inclusive)
        max: Maximum value (inclusive)

    Raises:
        FieldError: Invalid field value

    Returns:
        Parsed value
    """
    try:
        value = int(field)
        if not min <= value <= max:
            raise ValueError()

    except ValueError:
        raise FieldError(
            f"Can't parse an invalid field value: {field!r}. "
            f"Valid field values: {min}...{max} (inclusive)"
        )

    return value


def fixed_options_parser(options: Dict[str, T]) -> Callable[[str], T]:
    """
    Create a parser using a fixed set of options

    Args:
        options: Parsing options

    Returns:
        Bound parser function
    """
    def parser(field: str) -> T:
        return parse_from_options(field, options)
    return parser


def range_num_parser(min: int, max: int, wildcard: bool) -> Callable[[str], int]:
    """
    Create a parser using numeric range.

    Args:
        min: Minimum value (inclusive)
        max: Maximum value (inclusive)
        wildcard: Can field value be wildcard?

    Returns:
        Bound parser function
    """
    def parser(field: str) -> int:
        if wildcard and field == "*":
            return WILDCARD
        return parse_num_in_range(field, min, max)
    return parser
