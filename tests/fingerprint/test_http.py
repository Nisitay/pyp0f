from typing import Sequence

import pytest

from pyp0f.database.signatures.http import SignatureHeader
from pyp0f.fingerprint.http import fingerprint, headers_match
from pyp0f.net.layers.http import PacketHeader
from tests._packets import HTTP_PACKETS, HTTPTestPacket


class TestHeadersMatch:
    @staticmethod
    def _match(headers: Sequence[PacketHeader]) -> bool:
        return headers_match(
            (
                SignatureHeader(name=b"Server", is_optional=False),
                SignatureHeader(name=b"Date", is_optional=False),
                SignatureHeader(name=b"Content-Type", is_optional=False),
                SignatureHeader(name=b"Content-Length", is_optional=True),
                SignatureHeader(
                    name=b"Connection", is_optional=False, value=b"keep-alive"
                ),
            ),
            headers,
        )

    def test_simple(self):
        assert self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Content-Length", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )

    def test_case(self):
        assert self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"date", b""),
                PacketHeader(b"content-Type", b""),
                PacketHeader(b"content-Length", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )

    def test_with_optional(self):
        assert self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Content-Length", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )

    def test_without_optional(self):
        assert self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )

    def test_missing_header(self):
        assert not self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )

    def test_optional_in_wrong_order(self):
        assert not self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Connection", b"keep-alive"),
                PacketHeader(b"Content-Length", b""),
            )
        )

    def test_wrong_value(self):
        assert not self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Connection", b"foo"),
            )
        )

    def test_wrong_order(self):
        assert not self._match(
            (
                PacketHeader(b"Server", b""),
                PacketHeader(b"Content-Type", b""),
                PacketHeader(b"Date", b""),
                PacketHeader(b"Connection", b"keep-alive"),
            )
        )


@pytest.mark.parametrize(
    ("test_packet"),
    HTTP_PACKETS,
)
def test_fingerprint(test_packet: HTTPTestPacket):
    result = fingerprint(test_packet.payload)
    assert result.match is not None
    assert result.match.label.dump() == test_packet.expected_label
