from typing import Optional, Sequence

from pyp0f.utils.parse import WILDCARD
from pyp0f.records import HttpRecord
from pyp0f.net.packet import Direction
from pyp0f.options import Options, OPTIONS
from pyp0f.net.http import PacketHeader, SigHeader, BufferLike, read_payload
from pyp0f.signatures.http import HttpSig, HttpPacketSig

from .results import HttpResult


def headers_match(
    sig_headers: Sequence[SigHeader],
    pkt_headers: Sequence[PacketHeader]
) -> bool:
    """
    Check the ordering and values of headers.
    """
    i = 0  # Index of packet header

    for header in sig_headers:
        orig_index = i

        while (i < len(pkt_headers) and header.lower_name != pkt_headers[i].lower_name):
            i += 1

        if i == len(pkt_headers):  # header not in packet headers
            if not header.is_optional:
                return False

            # Optional header -> check that it doesn't appear anywhere else
            if any(
                header.lower_name == pkt_header.lower_name for pkt_header in pkt_headers
            ):
                return False

            i = orig_index
            continue

        # Header found, validate values
        if header.value is not None and header.value not in pkt_headers[i].value:
            return False
        i += 1
    return True


def signatures_match(sig: HttpSig, pkt_sig: HttpPacketSig) -> bool:
    """
    Check if HTTP signatures match by comparing the following criterias:
        - HTTP versions match.
        - All non-optional signature headers appear in the packet.
        - Absent headers in signature don't appear in the packet.
        - Order and values of headers match (this is relatively slow).
    """
    pkt_headers = pkt_sig.header_names()
    return (
        (sig.version == WILDCARD or sig.version == pkt_sig.version)
        and sig.header_names().issubset(pkt_headers)
        and not sig.absent_headers.intersection(pkt_headers)
        and headers_match(sig.headers, pkt_sig.headers)
    )


def find_match(
    pkt_sig: HttpPacketSig,
    direction: Direction,
    options: Options
) -> Optional[HttpRecord]:
    """
    Search through the database for a match for the given HTTP signature.
    """
    generic_match: Optional[HttpRecord] = None

    for http_record in options.database(HttpRecord, direction):
        if not signatures_match(http_record.signature, pkt_sig):
            continue

        if not http_record.is_generic:
            return http_record

        if generic_match is None:
            generic_match = http_record

    return generic_match


def fingerprint(buffer: BufferLike, options: Options = OPTIONS) -> HttpResult:
    """
    Fingerprint the given HTTP 1.x payload.

    Args:
        buffer: HTTP payload to fingerprint
        options: Fingerprint options. Defaults to OPTIONS.

    Raises:
        PacketError: The payload is invalid for HTTP fingerprint

    Returns:
        HTTP fingerprint result
    """
    direction, version, headers = read_payload(buffer)
    pkt_sig = HttpPacketSig(version, headers)
    return HttpResult(buffer, pkt_sig, find_match(pkt_sig, direction, options))
