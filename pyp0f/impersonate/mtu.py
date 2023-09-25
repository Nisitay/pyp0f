from typing import Optional

from pyp0f.database import Database
from pyp0f.database.records import MTURecord
from pyp0f.database.signatures import MTUSignature
from pyp0f.impersonate.utils import validate_for_impersonation
from pyp0f.net.layers.ip import IPV4
from pyp0f.net.layers.tcp import MIN_TCP4, MIN_TCP6
from pyp0f.net.scapy import ScapyPacket, ScapyTCP
from pyp0f.options import OPTIONS


def impersonate(
    packet: ScapyPacket,
    *,
    raw_label: Optional[str] = None,
    raw_signature: Optional[str] = None,
    database: Database = OPTIONS.database,
) -> ScapyPacket:
    """
    Modifies `packet` so that p0f will think it has been sent by a specific MTU.
    Either `raw_label` or `raw_signature` is required.

    If `raw_signature` is specified, we use the signature.
    signature format (as appears in database): `{mtu_value}`

    If only `raw_label` is specified, we randomly pick a signature with a label
    that matches `raw_label` (case sensitive!).

    Only TCP packets are supported.
    """
    validate_for_impersonation(packet)

    tcp = packet[ScapyTCP]

    if raw_signature is not None:
        signature = MTUSignature.parse(raw_signature)
    else:
        if raw_label is None:
            raise ValueError("raw_label or raw_signature is required to impersonate!")

        signature = database.get_random(raw_label, MTURecord).signature

    impersonated_value = (
        "MSS",
        signature.mtu - (MIN_TCP4 if packet.version == IPV4 else MIN_TCP6),
    )

    has_mss = dict(tcp.options).get("MSS") is not None

    tcp.options = (
        [impersonated_value if option[0] == "MSS" else option for option in tcp.options]
        if has_mss
        else [impersonated_value]
    )

    return packet
