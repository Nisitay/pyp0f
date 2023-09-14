from enum import Flag, auto
from typing import Optional, Tuple, TextIO, Type

from pyp0f.utils.path import PathLike
from pyp0f.utils.parse import split_parts, fixed_options_parser, parsing_error_wrapper
from pyp0f.exceptions import DatabaseError, ParsingError
from pyp0f.net.packet import Direction
from pyp0f.records import DatabaseLabel, Label, Record, MtuRecord, TcpRecord, HttpRecord

from .storage import RecordStorage


class ParserState(Flag):
    NEED_SECT = auto()
    NEED_LABEL = auto()
    NEED_SYS = auto()
    NEED_SIG = auto()


SKIPPED_LINES = {";", "\n"}
SKIPPED_PARAMS = {"classes", "ua_os"}

_parse_section_type = fixed_options_parser(
    {"mtu": MtuRecord, "tcp": TcpRecord, "http": HttpRecord}
)

_parse_direction = fixed_options_parser(
    {"request": Direction.CLI_TO_SRV, "response": Direction.SRV_TO_CLI}
)


def parse_file(filepath: PathLike) -> RecordStorage:
    """
    Parse records data from a p0f database file.

    Args:
        filepath: Database file path.

    Raises:
        DatabaseError: Can't open file

    Returns:
        p0f records storage
    """
    try:
        with open(filepath, mode="r", encoding="utf-8") as file:
            return _parse_file(file)
    except OSError as e:
        raise DatabaseError("Can't open database file for parsing") from e


def _parse_file(file: TextIO) -> RecordStorage:
    """
    Parse an open p0f database file.

    Args:
        file: Open database file

    Raises:
        ParsingError: Error while parsing database

    Returns:
        p0f records storage
    """
    storage = RecordStorage()
    state: ParserState = ParserState.NEED_SECT
    label: Optional[DatabaseLabel] = None
    direction: Optional[Direction] = None
    record_cls: Optional[Type[Record]] = None

    for line_no, line in enumerate(file, start=1):
        if line[0] in SKIPPED_LINES:
            continue

        line = line.strip()

        if line[0] == "[":
            with parsing_error_wrapper(line_no):
                record_cls, direction = _parse_section(line)
            storage.create(record_cls, direction)
            state = ParserState.NEED_LABEL
            continue

        param, _, val = line.partition("=")
        param = param.strip()
        val = val.strip()

        if param == "sig":
            if state != ParserState.NEED_SIG:
                raise ParsingError("Misplaced 'sig'", line_no)

            # record_cls & label are guaranteed to not be None
            with parsing_error_wrapper(line_no):
                record = record_cls(
                    label=label,
                    signature=record_cls._signature_cls.parse(val),  # type: ignore
                    raw_signature=val,
                    line_no=line_no,
                )

            storage.add(record, direction)

        elif param == "label":
            if state not in (ParserState.NEED_LABEL | ParserState.NEED_SIG):
                raise ParsingError("Misplaced 'label'", line_no)

            state = ParserState.NEED_SIG

            # record_cls is guaranteed to not be None
            with parsing_error_wrapper(line_no):
                label = record_cls._label_cls.parse(val)  # type: ignore

            if isinstance(label, Label) and label.is_user_app:
                state = ParserState.NEED_SYS

        elif param == "sys":
            if state != ParserState.NEED_SYS:
                raise ParsingError("Misplaced 'sys'", line_no)

            # label is guaranteed to be Label type
            label.sys = tuple(val.split(","))  # type: ignore
            state = ParserState.NEED_SIG

        elif param not in SKIPPED_PARAMS:
            raise ParsingError(f"Unrecognized field {param!r}", line_no)

    return storage


def _parse_section(line: str) -> Tuple[Type[Record], Optional[Direction]]:
    """
    Parse section entry. Returns the section and direction to use.
    """
    section_type, direction = split_parts(line[1:-1], parts=2)
    return (
        _parse_section_type(section_type),
        _parse_direction(direction) if direction else None,
    )
