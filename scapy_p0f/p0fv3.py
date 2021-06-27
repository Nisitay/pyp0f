from __future__ import absolute_import
from __future__ import print_function

from scapy.data import KnowledgeBase, select_path
from scapy.config import conf
from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.error import warning

from scapy_p0f.utils import lparse
from scapy_p0f.consts import MIN_TCP4, MIN_TCP6, MAX_DIST, WIN_TYPE_NORMAL, \
    WIN_TYPE_MOD, WIN_TYPE_MSS, WIN_TYPE_MTU
from scapy_p0f.types import TCP_Signature, HTTP_Signature, MTU_Record, \
    TCP_Record, HTTP_Record

_p0fpaths = ["/etc/p0f", "/usr/share/p0f", "/opt/local", "./common"]
conf.p0f_base = select_path(_p0fpaths, "p0f.fp")


class p0fKnowledgeBase(KnowledgeBase):
    """
    self.base = {
        "mtu" (str): [sig(tuple), ...]
        "tcp"/"http" (str): {
            direction (str): [sig(tuple), ...]
            }
    }
    self.labels = (label(tuple), ...)
    """
    def lazy_init(self):
        try:
            f = open(self.filename)
        except Exception:
            warning(("Can't open base %s. "
                     "Use p0fdb.reload(path_to_p0f) to set a custom p0f.fp path."), self.filename)  # noqa: E501
            return

        self.base = {}
        self.labels = []
        self._parse_file(f)
        self.labels = tuple(self.labels)
        f.close()

    def _parse_file(self, file):
        """
        Parses p0f.fp file and stores the data with described structures.
        """
        label_id = -1

        for line in file:
            if line[0] in (";", "\n"):
                continue
            line = line.strip()

            if line[0] == "[":
                section, direction = lparse(line[1:-1], 2)
                if section == "mtu":
                    self.base[section] = []
                    curr_records = self.base[section]
                else:
                    if section not in self.base:
                        self.base[section] = {direction: []}
                    elif direction not in self.base[section]:
                        self.base[section][direction] = []
                    curr_records = self.base[section][direction]
            else:
                param, _, val = line.partition(" = ")
                param = param.strip()

                if param == "sig":
                    if section == "mtu":
                        record_class = MTU_Record
                    elif section == "tcp":
                        record_class = TCP_Record
                    elif section == "http":
                        record_class = HTTP_Record
                    curr_records.append(record_class(label_id, val))

                elif param == "label":
                    label_id += 1
                    if section == "mtu":
                        self.labels.append(val)
                        continue
                    # label = type:class:name:flavor
                    t, c, name, flavor = lparse(val, 4)
                    self.labels.append((t, c, name, flavor))

                elif param == "sys":
                    sys_names = tuple(name for name in val.split(","))
                    self.labels[label_id] += (sys_names,)

    def tcp_find_match(self, ts, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dist: guessed distance from the packet source
        - fuzzy: whether the match is fuzzy
        Returns None if no match was found
        """
        win_multi, use_mtu = detect_win_multi(ts)

        gmatch = None  # generic match
        fmatch = None  # fuzzy match
        for tcp_record in self.base["tcp"][direction]:
            rs = tcp_record.sig

            fuzzy = False
            ref_quirks = rs.quirks

            if rs.olayout != ts.olayout:
                continue

            if rs.ip_ver == -1:
                ref_quirks -= {"flow"} if ts.ip_ver == 4 else {"df", "id+", "id-"}  # noqa: E501

            if ref_quirks != ts.quirks:
                deleted = (ref_quirks ^ ts.quirks) & ref_quirks
                added = (ref_quirks ^ ts.quirks) & ts.quirks

                if (fmatch or (deleted - {"df", "id+"}) or (added - {"id-", "ecn"})):  # noqa: E501
                    continue
                fuzzy = True

            if rs.ip_opt_len != ts.ip_opt_len:
                continue
            if tcp_record.bad_ttl:
                if rs.ttl < ts.ttl:
                    continue
            else:
                if rs.ttl < ts.ttl or rs.ttl - ts.ttl > MAX_DIST:
                    fuzzy = True

            if ((rs.mss != -1 and rs.mss != ts.mss) or
               (rs.wscale != -1 and rs.wscale != ts.wscale) or
               (rs.pay_class != -1 and rs.pay_class != ts.pay_class)):
                continue

            if rs.win_type == WIN_TYPE_NORMAL:
                if rs.win != ts.win:
                    continue
            elif rs.win_type == WIN_TYPE_MOD:
                if ts.win % rs.win:
                    continue
            elif rs.win_type == WIN_TYPE_MSS:
                if (use_mtu or rs.win != win_multi):
                    continue
            elif rs.win_type == WIN_TYPE_MTU:
                if (not use_mtu or rs.win != win_multi):
                    continue

            # Got a match? If not fuzzy, return. If fuzzy, keep looking.
            label = self.labels[tcp_record.label_id]
            if not fuzzy:
                if label[0] == "s":
                    return (label, rs.ttl - ts.ttl, fuzzy)
                elif not gmatch:
                    gmatch = (label, rs.ttl - ts.ttl, fuzzy)
            elif not fmatch:
                fmatch = (label, rs.ttl - ts.ttl, fuzzy)

        if gmatch:
            return gmatch
        if fmatch:
            return fmatch
        return None

    def http_find_match(self, ts, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dishonest: whether the software was detected as dishonest
        Returns None if no match was found
        """
        gmatch = None  # generic match
        for http_record in self.base["http"][direction]:
            rs = http_record.sig

            if rs.http_ver != -1 and rs.http_ver != ts.http_ver:
                continue

            # Check that all non-optional headers appear in the packet
            if not (ts.hdr_set & rs.hdr_set) == rs.hdr_set:
                continue

            # Check that no forbidden headers appear in the packet.
            if len(rs.habsent & ts.hdr_set) > 0:
                continue

            def headers_correl():
                phi = 0  # Packet HTTP header index
                hdr_len = len(ts.hdr)

                # Confirm the ordering and values of headers
                # (this is relatively slow, hence the if statements above).
                # The algorithm is derived from the original p0f/fp_http.c
                for kh in rs.hdr:
                    orig_phi = phi
                    while (phi < hdr_len and
                           kh[0] != ts.hdr[phi][0]):
                        phi += 1

                    if phi == hdr_len:
                        if not kh[2]:
                            return False

                        for ph in ts.hdr:
                            if kh[0] == ph[0]:
                                return False

                        phi = orig_phi
                        continue

                    if kh[1] not in ts.hdr[phi][1]:
                        return False
                    phi += 1
                return True

            if not headers_correl():
                continue

            # Got a match
            label = self.labels[http_record.label_id]
            dishonest = rs.sw and ts.sw and rs.sw not in ts.sw

            if label[0] == "s":
                return label, dishonest
            elif not gmatch:
                gmatch = (label, dishonest)
        return gmatch if gmatch else None

    def mtu_find_match(self, mtu):
        """
        Finds a match for the given MTU.
        If a match is found, returns the label string.
        Returns None if no match was found
        """
        for mtu_record in self.base["mtu"]:
            if mtu == mtu_record.mtu:
                return self.labels[mtu_record.label_id]
        return None


p0fdb = p0fKnowledgeBase(conf.p0f_base)


def preprocess_packet(pkt):
    """
    Creates a copy of the packet and checks if the packet is
    an IPv4/IPv6 and TCP packet. If the packet is valid,
    the copy is returned. If not, TypeError is raised.
    """
    pkt = pkt.copy()
    pkt = pkt.__class__(raw(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if ((not isinstance(pkt, IPv6) and not isinstance(pkt, IP)) or
       not isinstance(pkt.payload, TCP)):
        raise TypeError("Not a TCP/IP packet")
    return pkt


def detect_win_multi(ts):
    """
    Figure out if window size is a multiplier of MSS or MTU.
    Receives a TCP signature and returns the multiplier and
    whether mtu should be used
    """
    mss = ts.mss
    win = ts.win
    if not win or mss < 100:
        return -1, False

    options = [
        (mss, False),
        (1500 - MIN_TCP4, False),
        (1500 - MIN_TCP4 - 12, False),
        (mss + MIN_TCP4, True),
        (1500, True)
    ]
    if ts.ts1:
        options.append((mss - 12, False))
    if ts.ip_ver == 6:
        options.append((1500 - MIN_TCP6, False))
        options.append((1500 - MIN_TCP6 - 12, False))
        options.append((mss + MIN_TCP6, True))

    for div, use_mtu in options:
        if not win % div:
            return win / div, use_mtu
    return -1, False


def packet2p0f(pkt):
    """
    Returns a p0f signature of the packet, and the direction.
    Raises TypeError if the packet isn't valid for p0f
    """
    pkt = preprocess_packet(pkt)

    if pkt[TCP].flags.S:
        if pkt[TCP].flags.A:
            direction = "response"
        else:
            direction = "request"
        sig = TCP_Signature.from_packet(pkt)

    elif pkt[TCP].payload:
        # XXX: guess_payload_class doesn't use any class related attributes
        pclass = HTTP().guess_payload_class(raw(pkt[TCP].payload))
        if pclass == HTTPRequest:
            direction = "request"
        elif pclass == HTTPResponse:
            direction = "response"
        else:
            raise TypeError("Not an HTTP payload")
        sig = HTTP_Signature.from_packet(pkt)
    else:
        raise TypeError("Not a SYN, SYN/ACK, or HTTP packet")
    return sig, direction


def fingerprint_mtu(pkt):
    """
    Fingerprints the MTU based on the maximum segment size specified
    in TCP options.
    If a match was found, returns the label. If not returns None
    """
    pkt = preprocess_packet(pkt)
    mss = 0
    for name, value in pkt.payload.options:
        if name == "MSS":
            mss = value

    if not mss:
        return None

    mtu = (mss + MIN_TCP4) if pkt.version == 4 else (mss + MIN_TCP6)

    if not p0fdb.get_base():
        warning("p0f base empty.")
        return None

    return p0fdb.mtu_find_match(mtu)


def p0f(pkt):
    """
    Passive fingerprinting: which OS/App emitted this TCP packet?
    Receives a packet and returns a match as a tuple, or None if
    no match was found
    """
    sig, direction = packet2p0f(pkt)
    if not p0fdb.get_base():
        warning("p0f base empty.")
        return None

    if isinstance(sig, TCP_Signature):
        return p0fdb.tcp_find_match(sig, direction)
    else:
        return p0fdb.http_find_match(sig, direction)


def prnp0f(pkt):
    """Calls p0f and returns a user-friendly output"""
    try:
        r = p0f(pkt)
    except Exception:
        return

    sig, direction = packet2p0f(pkt)
    is_tcp_sig = isinstance(sig, TCP_Signature)
    to_server = direction == "request"

    if is_tcp_sig:
        pkt_type = "SYN" if to_server else "SYN+ACK"
    else:
        pkt_type = "HTTP Request" if to_server else "HTTP Response"

    res = pkt.sprintf(".-[ %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport% (" + pkt_type + ") ]-\n|\n")  # noqa: E501
    fields = []

    def add_field(name, value):
        fields.append("| %-8s = %s\n" % (name, value))

    cli_or_svr = "Client" if to_server else "Server"
    add_field(cli_or_svr, pkt.sprintf("%IP.src%:%TCP.sport%"))

    if r:
        label = r[0]
        app_or_os = "App" if label[1] == "!" else "OS"
        add_field(app_or_os, label[2] + " " + label[3])
        if len(label) == 5:  # label includes sys
            add_field("Sys", ", ".join(name for name in label[4]))
        if is_tcp_sig:
            add_field("Distance", r[1])
    else:
        app_or_os = "OS" if is_tcp_sig else "App"
        add_field(app_or_os, "UNKNOWN")

    add_field("Raw sig", str(sig))

    res += "".join(fields)
    res += "`____\n"
    print(res)
