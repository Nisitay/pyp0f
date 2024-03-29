import re
from typing import Iterable, List, Tuple, Union

from h11._receivebuffer import ReceiveBuffer

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.http.header import PacketHeader
from pyp0f.net.packet import Direction

BufferLike = Union[ReceiveBuffer, bytes, bytearray]

CRLF = b"\r\n"
HTTP_VERSION_PATTERN = re.compile(rb"^HTTP/1\.(?P<version>\d)$")


def copy_buffer(buffer: BufferLike) -> ReceiveBuffer:
    """
    Copy the given buffer to not modify passed buffer when extracting lines.
    """
    buffer_copy = ReceiveBuffer()
    buffer_copy += bytes(buffer)
    return buffer_copy


def extract_minor_version(http_version: bytes) -> int:
    """
    Extract minor HTTP 1.x version.

    Args:
        http_version (bytes): Raw HTTP 1.x version field

    Raises:
        PacketError: The HTTP version isn't 1.x

    Returns:
        Minor HTTP version
    """
    match = HTTP_VERSION_PATTERN.match(http_version)

    if match is None:
        raise PacketError(f"Unknown HTTP version: {http_version!r}")

    return int(match.group("version"))


def read_first_line(line: bytes) -> Tuple[Direction, int]:
    """
    Read first HTTP request/response line.
    We only care about GET and HEAD requests, other request types raise `PacketError`.

    Args:
        line: First line of HTTP request/response

    Raises:
        PacketError: Bad HTTP first line

    Returns:
        Direction of the message, and the minor HTTP version
    """
    try:
        parts = line.split(None, maxsplit=2)

        if parts[0] in (b"GET", b"HEAD"):
            direction = Direction.CLIENT_TO_SERVER
            raw_http_version = parts[2]
        else:
            direction = Direction.SERVER_TO_CLIENT
            raw_http_version = parts[0]

        http_version = extract_minor_version(raw_http_version)

    except (PacketError, ValueError, IndexError) as e:
        raise PacketError(f"Bad HTTP first line: {line!r}") from e

    return direction, http_version


def read_headers(lines: Iterable[bytes]) -> List[PacketHeader]:
    """
    Read a set of headers.
    Stop once a blank line is reached.

    Args:
        lines: Raw headers lines

    Raises:
        PacketError: Invalid header

    Returns:
        List of packet headers
    """
    headers: List[PacketHeader] = []

    for line in lines:
        if line[0] in b" \t":
            if not headers:
                raise PacketError("Invalid headers")

            # Continued header
            headers[-1] = PacketHeader(
                name=headers[-1].name,
                value=headers[-1].value + CRLF + b" " + line.strip(),
            )
        else:
            try:
                name, value = line.split(b":", maxsplit=1)

                if not name:
                    raise ValueError("Empty header name")

                headers.append(PacketHeader(name=name, value=value.strip()))
            except ValueError as e:
                raise PacketError(f"Invalid header line: {line!r}") from e

    return headers


def read_payload(
    buffer: BufferLike,
) -> Tuple[Direction, int, List[PacketHeader]]:
    """
    Read HTTP payload (first line + headers) from a buffer.

    Args:
        buffer: The input buffer

    Raises:
        PacketError: Not an HTTP payload, or an invalid one

    Returns:
        Direction of the message, minor HTTP version, parsed headers
    """
    lines = copy_buffer(buffer).maybe_extract_lines()

    if lines is None:
        raise PacketError("Not an HTTP payload, or payload not complete")

    lines = [bytes(line) for line in lines]

    direction, minor_http_version = read_first_line(lines[0])

    return direction, minor_http_version, read_headers(lines[1:])
