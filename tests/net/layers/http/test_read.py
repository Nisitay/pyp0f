import pytest

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.http.header import PacketHeader
from pyp0f.net.layers.http.read import (
    extract_minor_version,
    read_first_line,
    read_headers,
)
from pyp0f.net.packet import Direction


def test_extract_minor_version():
    assert extract_minor_version(b"HTTP/1.1") == 1
    assert extract_minor_version(b"HTTP/1.0") == 0

    with pytest.raises(PacketError):
        extract_minor_version(b"HTTP/2")


class TestReadFirstLine:
    def test_read_request(self):
        assert read_first_line(b"GET / HTTP/1.1") == (Direction.CLIENT_TO_SERVER, 1)
        assert read_first_line(b"HEAD / HTTP/1.0") == (Direction.CLIENT_TO_SERVER, 0)

    def test_read_response(self):
        assert read_first_line(b"HTTP/1.1 200 OK") == (Direction.SERVER_TO_CLIENT, 1)
        assert read_first_line(b"HTTP/1.0 200") == (Direction.SERVER_TO_CLIENT, 0)

    def test_read_request_invalid_method(self):
        with pytest.raises(PacketError):
            read_first_line(b"POST / HTTP/1.1")

        with pytest.raises(PacketError):
            read_first_line(b"PUT / HTTP/1.0")


class TestReadHeaders:
    @staticmethod
    def _read(data: bytes):
        return read_headers(data.splitlines(keepends=True))

    def test_read(self):
        assert self._read(b"Name1: value1\r\nName2: value2\r\n") == [
            PacketHeader(b"Name1", b"value1"),
            PacketHeader(b"Name2", b"value2"),
        ]

    def test_read_continued(self):
        assert self._read(b"Name: value\r\n" b"\tmore\r\n" b"nName2: value\r\n") == [
            PacketHeader(b"Name", b"value\r\n more"),
            PacketHeader(b"nName2", b"value"),
        ]

    def test_read_continued_err(self):
        with pytest.raises(PacketError):
            self._read(b"\tName: value\r\n")

    def test_read_err(self):
        with pytest.raises(PacketError):
            self._read(b"Name")

    def test_read_empty_name(self):
        with pytest.raises(PacketError):
            self._read(b":value")

    def test_read_empty_value(self):
        assert self._read(b"Name:") == [PacketHeader(b"Name", b"")]
