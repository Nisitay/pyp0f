import re
import struct

from scapy.compat import raw, orb
from scapy.layers.inet import TCP, TCPOptions

from scapy_p0f.utils import lparse, guess_dist
from scapy_p0f.consts import WIN_TYPE_NORMAL, WIN_TYPE_ANY, WIN_TYPE_MOD, \
    WIN_TYPE_MSS, WIN_TYPE_MTU


# Convert TCP option num to p0f (nop is handeled seperately)
tcp_options_p0f = {
    2: "mss",  # maximum segment size
    3: "ws",  # window scaling
    4: "sok",  # selective ACK permitted
    5: "sack",  # selective ACK (should not be seen)
    8: "ts",  # timestamp
}


# Signatures
class TCP_Signature(object):
    __slots__ = ["olayout", "quirks", "ip_opt_len", "ip_ver", "ttl",
                 "mss", "win", "win_type", "wscale", "pay_class", "ts1"]

    def __init__(self, olayout, quirks, ip_opt_len, ip_ver, ttl,
                 mss, win, win_type, wscale, pay_class, ts1):
        self.olayout = olayout
        self.quirks = quirks
        self.ip_opt_len = ip_opt_len
        self.ip_ver = ip_ver
        self.ttl = ttl
        self.mss = mss
        self.win = win
        self.win_type = win_type  # None for packet signatures
        self.wscale = wscale
        self.pay_class = pay_class
        self.ts1 = ts1  # None for base signatures

    @classmethod
    def from_packet(cls, pkt):
        """
        Receives a TCP packet (assuming it's valid), and returns
        a TCP_Signature object
        """
        ip_ver = pkt.version
        quirks = set()

        def addq(name):
            quirks.add(name)

        # IPv4/IPv6 parsing
        if ip_ver == 4:
            ttl = pkt.ttl
            ip_opt_len = (pkt.ihl * 4) - 20
            if pkt.tos & (0x01 | 0x02):
                addq("ecn")
            if pkt.flags.evil:
                addq("0+")
            if pkt.flags.DF:
                addq("df")
                if pkt.id:
                    addq("id+")
            elif pkt.id == 0:
                addq("id-")
        else:
            ttl = pkt.hlim
            ip_opt_len = 0
            if pkt.fl:
                addq("flow")
            if pkt.tc & (0x01 | 0x02):
                addq("ecn")

        # TCP parsing
        tcp = pkt[TCP]
        win = tcp.window
        if tcp.flags & (0x40 | 0x80 | 0x01):
            addq("ecn")
        if tcp.seq == 0:
            addq("seq-")
        if tcp.flags.A:
            if tcp.ack == 0:
                addq("ack-")
        elif tcp.ack:
            addq("ack+")
        if tcp.flags.U:
            addq("urgf+")
        elif tcp.urgptr:
            addq("uptr+")
        if tcp.flags.P:
            addq("pushf+")

        pay_class = 1 if tcp.payload else 0

        # Manual TCP options parsing
        mss = 0
        wscale = 0
        ts1 = 0
        olayout = ""
        optlen = (tcp.dataofs << 2) - 20
        x = raw(tcp)[-optlen:]  # raw bytes of TCP options
        while x:
            onum = orb(x[0])
            if onum == 0:
                x = x[1:]
                olayout += "eol+%i," % len(x)
                if x.strip(b"\x00"):  # non-zero past EOL
                    addq("opt+")
                break
            if onum == 1:
                x = x[1:]
                olayout += "nop,"
                continue
            try:
                olen = orb(x[1])
            except IndexError:  # no room for length field
                addq("bad")
                break
            oval = x[2:olen]
            if onum in tcp_options_p0f:
                ofmt = TCPOptions[0][onum][1]
                olayout += "%s," % tcp_options_p0f[onum]
                optsize = 2 + struct.calcsize(ofmt) if ofmt else 2  # total len
                if len(x) < optsize:  # option would end past end of header
                    addq("bad")
                    break

                if onum == 5:
                    if olen < 10 or olen > 34:  # SACK length out of range
                        addq("bad")
                        break
                else:
                    if olen != optsize:  # length field doesn't fit option type
                        addq("bad")
                        break
                    if ofmt:
                        oval = struct.unpack(ofmt, oval)
                        if len(oval) == 1:
                            oval = oval[0]
                    if onum == 2:
                        mss = oval
                    elif onum == 3:
                        wscale = oval
                        if wscale > 14:
                            addq("exws")
                    elif onum == 8:
                        ts1 = oval[0]
                        if not ts1:
                            addq("ts1-")
                        if oval[1] and (tcp.flags.S and not tcp.flags.A):
                            addq("ts2+")
            else:  # Unknown option, presumably with specified size
                if olen < 2 or olen > 40 or olen > len(x):
                    addq("bad")
                    break
            x = x[olen:]
        olayout = olayout[:-1]

        return cls(olayout, quirks, ip_opt_len, ip_ver, ttl, mss, win, None, wscale, pay_class, ts1)  # noqa: E501

    @classmethod
    def from_raw_sig(cls, sig_line):
        """
        Parses a TCP sig line and returns a tuple consisting of a
        TCP_Signature object and bad_ttl as bool
        """
        ver, ttl, olen, mss, wsize, olayout, quirks, pclass = lparse(sig_line, 8)  # noqa: E501
        wsize, _, scale = wsize.partition(",")

        ip_ver = -1 if ver == "*" else int(ver)
        ttl, bad_ttl = (int(ttl[:-1]), True) if ttl[-1] == "-" else (int(ttl), False)  # noqa: E501
        ip_opt_len = int(olen)
        mss = -1 if mss == "*" else int(mss)
        if wsize == "*":
            win, win_type = (0, WIN_TYPE_ANY)
        elif wsize[:3] == "mss":
            win, win_type = (int(wsize[4:]), WIN_TYPE_MSS)
        elif wsize[0] == "%":
            win, win_type = (int(wsize[1:]), WIN_TYPE_MOD)
        elif wsize[:3] == "mtu":
            win, win_type = (int(wsize[4:]), WIN_TYPE_MTU)
        else:
            win, win_type = (int(wsize), WIN_TYPE_NORMAL)
        wscale = -1 if scale == "*" else int(scale)
        if quirks:
            quirks = frozenset(q for q in quirks.split(","))
        else:
            quirks = frozenset()
        pay_class = -1 if pclass == "*" else int(pclass == "+")

        sig = cls(olayout, quirks, ip_opt_len, ip_ver, ttl, mss, win, win_type, wscale, pay_class, None)  # noqa: E501
        return sig, bad_ttl

    def __str__(self):
        quirks = ",".join(q for q in self.quirks)
        fmt = "%i:%i+%i:%i:%i:%i,%i:%s:%s:%i"
        s = fmt % (self.ip_ver, self.ttl, guess_dist(self.ttl),
                   self.ip_opt_len, self.mss, self.win, self.wscale,
                   self.olayout, quirks, self.pay_class)
        return s


class HTTP_Signature(object):
    __slots__ = ["http_ver", "hdr", "hdr_set", "habsent", "sw"]

    def __init__(self, http_ver, hdr, hdr_set, habsent, sw):
        self.http_ver = http_ver
        self.hdr = hdr
        self.hdr_set = hdr_set
        self.habsent = habsent  # None for packet signatures
        self.sw = sw

    @classmethod
    def from_packet(cls, pkt):
        """
        Receives an HTTP packet (assuming it's valid), and returns
        a HTTP_Signature object
        """
        http_payload = raw(pkt[TCP].payload)

        crlfcrlf = b"\r\n\r\n"
        crlfcrlfIndex = http_payload.find(crlfcrlf)
        if crlfcrlfIndex != -1:
            headers = http_payload[:crlfcrlfIndex + len(crlfcrlf)]
        else:
            headers = http_payload
        headers = headers.decode()  # XXX: Check if this could fail
        first_line, headers = headers.split("\r\n", 1)

        if "1.0" in first_line:
            http_ver = 0
        elif "1.1" in first_line:
            http_ver = 1
        else:
            raise ValueError("HTTP version is not 1.0/1.1")

        sw = ""
        headers_found = []
        hdr_set = set()
        for header_line in headers.split("\r\n"):
            name, _, value = header_line.partition(":")
            if value:
                value = value.strip()
                headers_found.append((name, value))
                hdr_set.add(name)
                if name in ("User-Agent", "Server"):
                    sw = value
        hdr = tuple(headers_found)
        return cls(http_ver, hdr, hdr_set, None, sw)

    @classmethod
    def from_raw_sig(cls, sig_line):
        """
        Parses an HTTP sig line and returns a HTTP_Signature object
        """
        ver, horder, habsent, expsw = lparse(sig_line, 4)
        http_ver = -1 if ver == "*" else int(ver)

        # horder parsing - split by commas that aren't in []
        new_horder = []
        for header in re.split(r",(?![^\[]*\])", horder):
            name, _, value = header.partition("=")
            if name[0] == "?":  # Optional header
                new_horder.append((name[1:], value[1:-1], True))
            else:
                new_horder.append((name, value[1:-1], False))
        hdr = tuple(new_horder)
        hdr_set = frozenset(header[0] for header in hdr if not header[2])
        habsent = frozenset(habsent.split(","))
        return cls(http_ver, hdr, hdr_set, habsent, expsw)

    def __str__(self):
        # values that depend on the context are not included in the string
        skipval = ("Host", "User-Agent", "Date", "Content-Type", "Server")
        hdr = ",".join(n if n in skipval else "%s=[%s]" % (n, v) for n, v in self.hdr)  # noqa: E501
        fmt = "%i:%s::%s"
        s = fmt % (self.http_ver, hdr, self.sw)
        return s


# Records
class MTU_Record(object):
    __slots__ = ["label_id", "mtu"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        self.mtu = int(sig_line)


class TCP_Record(object):
    __slots__ = ["label_id", "bad_ttl", "sig"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        sig, bad_ttl = TCP_Signature.from_raw_sig(sig_line)
        self.bad_ttl = bad_ttl
        self.sig = sig


class HTTP_Record(object):
    __slots__ = ["label_id", "sig"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        self.sig = HTTP_Signature.from_raw_sig(sig_line)
