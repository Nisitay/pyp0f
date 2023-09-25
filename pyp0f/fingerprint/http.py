from typing import Optional, Sequence

from pyp0f.database import Database
from pyp0f.database.parse.utils import WILDCARD
from pyp0f.database.records import HTTPRecord
from pyp0f.database.signatures import HTTPSignature, SignatureHeader
from pyp0f.fingerprint.results import HTTPResult
from pyp0f.net.layers.http import BufferLike, PacketHeader, read_payload
from pyp0f.net.packet import Direction
from pyp0f.net.signatures import HTTPPacketSignature
from pyp0f.options import OPTIONS, Options


def headers_match(
    signature_headers: Sequence[SignatureHeader], packet_headers: Sequence[PacketHeader]
) -> bool:
    """
    Check the ordering and values of headers.
    """
    i = 0  # Index of packet header

    for header in signature_headers:
        orig_index = i

        while (
            i < len(packet_headers)
            and header.lower_name != packet_headers[i].lower_name
        ):
            i += 1

        if i == len(packet_headers):  # header not in packet headers
            if not header.is_optional:
                return False

            # Optional header -> check that it doesn't appear anywhere else
            if any(
                header.lower_name == pkt_header.lower_name
                for pkt_header in packet_headers
            ):
                return False

            i = orig_index
            continue

        # Header found, validate values
        if header.value is not None and header.value not in packet_headers[i].value:
            return False
        i += 1
    return True


def signatures_match(
    signature: HTTPSignature, packet_signature: HTTPPacketSignature
) -> bool:
    """
    Check if HTTP signatures match by comparing the following criterias:
        - HTTP versions match.
        - All non-optional signature headers appear in the packet.
        - Absent headers in signature don't appear in the packet.
        - Order and values of headers match (this is relatively slow).
    """
    packet_headers = packet_signature.header_names
    return (
        (signature.version == WILDCARD or signature.version == packet_signature.version)
        and signature.header_names.issubset(packet_headers)
        and not signature.absent_headers.intersection(packet_headers)
        and headers_match(signature.headers, packet_signature.headers)
    )


def find_match(
    packet_signature: HTTPPacketSignature,
    direction: Direction,
    database: Database,
) -> Optional[HTTPRecord]:
    """
    Search through the database for a match for the given HTTP signature.
    """
    generic_match: Optional[HTTPRecord] = None

    for http_record in database.iter_values(HTTPRecord, direction):
        if not signatures_match(http_record.signature, packet_signature):
            continue

        if not http_record.is_generic:
            return http_record

        if generic_match is None:
            generic_match = http_record

    return generic_match


def fingerprint(buffer: BufferLike, options: Options = OPTIONS) -> HTTPResult:
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
    packet_signature = HTTPPacketSignature(version, headers)

    return HTTPResult(
        buffer,
        packet_signature,
        find_match(packet_signature, direction, options.database),
    )
