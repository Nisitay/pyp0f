from enum import Flag, auto


class Quirk(Flag):
    # IP quirks
    ECN = auto()  # ECN supported
    DF = auto()  # DF used (probably PMTUD)
    NZ_ID = auto()  # Non-zero IDs when DF set
    ZERO_ID = auto()  # Zero IDs when DF not set
    NZ_MBZ = auto()  # IP "must be zero" field isn't
    FLOW = auto()  # IPv6 flows used

    # Core TCP quirks
    ZERO_SEQ = auto()  # SEQ is zero
    NZ_ACK = auto()  # ACK non-zero when ACK flag not set
    ZERO_ACK = auto()  # ACK is zero when ACK flag set
    NZ_URG = auto()  # URG non-zero when URG flag not set
    URG = auto()  # URG flag set
    PUSH = auto()  # PUSH flag on a control packet

    # TCP option quirks
    OPT_ZERO_TS1 = auto()  # Own timestamp set to zero
    OPT_NZ_TS2 = auto()  # Peer timestamp non-zero on SYN
    OPT_EOL_NZ = auto()  # Non-zero padding past EOL
    OPT_EXWS = auto()  # Excessive window scaling
    OPT_BAD = auto()  # Problem parsing TCP options


QUIRK_STRINGS = {
    Quirk.ECN: "ecn",
    Quirk.DF: "df",
    Quirk.NZ_ID: "id+",
    Quirk.ZERO_ID: "id-",
    Quirk.NZ_MBZ: "0+",
    Quirk.FLOW: "flow",
    Quirk.ZERO_SEQ: "seq-",
    Quirk.NZ_ACK: "ack+",
    Quirk.ZERO_ACK: "ack-",
    Quirk.NZ_URG: "uptr+",
    Quirk.URG: "urgf+",
    Quirk.PUSH: "pushf+",
    Quirk.OPT_ZERO_TS1: "ts1-",
    Quirk.OPT_NZ_TS2: "ts2+",
    Quirk.OPT_EOL_NZ: "opt+",
    Quirk.OPT_EXWS: "exws",
    Quirk.OPT_BAD: "bad",
}


def dump_quirks(quirks: Quirk) -> str:
    """
    Dump quirks field to p0f representation.
    """
    return ",".join(s for quirk, s in QUIRK_STRINGS.items() if quirk in quirks)
