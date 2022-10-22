import pytest
from typing import Sequence

from pyp0f.net.http import PacketHeader, SigHeader
from pyp0f.fingerprint.http import fingerprint, headers_match

from tests._packets.http import WGET, NGINX, APACHE


class TestHeadersMatch:
    @staticmethod
    def _match(headers: Sequence[PacketHeader]) -> bool:
        return headers_match((
            SigHeader(name=b"Server", is_optional=False),
            SigHeader(name=b"Date", is_optional=False),
            SigHeader(name=b"Content-Type", is_optional=False),
            SigHeader(name=b"Content-Length", is_optional=True),
            SigHeader(name=b"Connection", is_optional=False, value=b"keep-alive")
        ), headers)

    def test_simple(self):
        assert self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Content-Length", b""),
            PacketHeader(b"Connection", b"keep-alive")
        ))

    def test_case(self):
        assert self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"date", b""),
            PacketHeader(b"content-Type", b""),
            PacketHeader(b"content-Length", b""),
            PacketHeader(b"Connection", b"keep-alive")
        ))

    def test_with_optional(self):
        assert self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Content-Length", b""),
            PacketHeader(b"Connection", b"keep-alive")
        ))

    def test_without_optional(self):
        assert self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Connection", b"keep-alive")
        ))

    def test_missing_header(self):
        assert not self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Connection", b"keep-alive")
        ))

    def test_optional_in_wrong_order(self):
        assert not self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Connection", b"keep-alive"),
            PacketHeader(b"Content-Length", b"")
        ))

    def test_wrong_value(self):
        assert not self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Connection", b"foo"),
        ))

    def test_wrong_order(self):
        assert not self._match((
            PacketHeader(b"Server", b""),
            PacketHeader(b"Content-Type", b""),
            PacketHeader(b"Date", b""),
            PacketHeader(b"Connection", b"keep-alive"),
        ))


@pytest.mark.parametrize(
    ("buffer", "expected_label"),
    [
        (WGET, "s:!:wget:"),
        (NGINX, "s:!:nginx:1.x"),
        (APACHE, "s:!:Apache:2.x")
    ]
)
def test_fingerprint(buffer: bytes, expected_label: str):
    res = fingerprint(buffer)
    assert res.match is not None
    assert res.match.label.dump() == expected_label
