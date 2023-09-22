from enum import Flag, auto
from typing import Optional, TextIO, Tuple, Type

from pyp0f.database.labels import DatabaseLabel, Label
from pyp0f.database.parse.utils import (
    fixed_options_parser,
    parsing_error_wrapper,
    split_parts,
)
from pyp0f.database.records import HTTPRecord, MTURecord, Record, TCPRecord
from pyp0f.database.records_database import RecordsDatabase
from pyp0f.exceptions import DatabaseError, ParsingError
from pyp0f.net.packet import Direction
from pyp0f.utils.path import PathLike

# TODO: Parse params
SKIPPED_PARAMS = {"classes", "ua_os"}
SKIPPED_LINES = {";", "\n"}

_parse_section_type = fixed_options_parser(
    {"mtu": MTURecord, "tcp": TCPRecord, "http": HTTPRecord}
)

_parse_direction = fixed_options_parser(
    {"request": Direction.CLIENT_TO_SERVER, "response": Direction.SERVER_TO_CLIENT}
)


class ParserState(Flag):
    NEED_SECTION = auto()
    NEED_LABEL = auto()
    NEED_SYS = auto()
    NEED_SIG = auto()


def parse_file(filepath: PathLike) -> RecordsDatabase:
    """
    Parse records data from a p0f database file.

    Args:
        filepath: Database file path.

    Raises:
        DatabaseError: Can't open file

    Returns:
        p0f records database
    """
    try:
        with open(filepath, mode="r", encoding="utf-8") as file:
            return _parse_file(file)
    except OSError as e:
        raise DatabaseError("Can't open database file for parsing") from e


def _parse_file(file: TextIO) -> RecordsDatabase:
    database = RecordsDatabase()
    state: ParserState = ParserState.NEED_SECTION
    label: Optional[DatabaseLabel] = None
    direction: Optional[Direction] = None
    record_cls: Optional[Type[Record]] = None

    for line_number, line in enumerate(file, start=1):
        if line[0] in SKIPPED_LINES:
            continue

        line = line.strip()

        if line[0] == "[":
            with parsing_error_wrapper(line_number):
                record_cls, direction = _parse_section(line)

            database.create(record_cls, direction)
            state = ParserState.NEED_LABEL
            continue

        parameter, _, value = line.partition("=")
        parameter = parameter.strip()
        value = value.strip()

        if parameter == "sig":
            if state != ParserState.NEED_SIG or record_cls is None:
                raise ParsingError("Misplaced 'sig'", line_number)

            with parsing_error_wrapper(line_number):
                record = record_cls(
                    label=label,
                    signature=record_cls._signature_cls.parse(value),
                    raw_signature=value,
                    line_number=line_number,
                )

            database.add(record, direction)

        elif parameter == "label":
            if (
                state not in (ParserState.NEED_LABEL | ParserState.NEED_SIG)
                or record_cls is None
            ):
                raise ParsingError("Misplaced 'label'", line_number)

            state = ParserState.NEED_SIG

            with parsing_error_wrapper(line_number):
                label = record_cls._label_cls.parse(value)

            if isinstance(label, Label) and label.is_user_app:
                state = ParserState.NEED_SYS

        elif parameter == "sys":
            if state != ParserState.NEED_SYS or not isinstance(label, Label):
                raise ParsingError("Misplaced 'sys'", line_number)

            label.sys = tuple(value.split(","))
            state = ParserState.NEED_SIG

        elif parameter not in SKIPPED_PARAMS:
            raise ParsingError(f"Unrecognized field {parameter!r}", line_number)

    return database


def _parse_section(line: str) -> Tuple[Type[Record], Optional[Direction]]:
    """
    Parse section entry. Returns the section record type and direction to use.
    """
    section_type, direction = split_parts(line[1:-1], parts=2)

    return (
        _parse_section_type(section_type),
        _parse_direction(direction) if direction else None,
    )
