import unittest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from scapy_p0f.p0fv3 import p0f


class Test_TCP_p0f(unittest.TestCase):
    def test_windows_syn(self):
        pkt = IP(b'E\x00\x004Se@\x00\x80\x06\x93?\n\x00\x00\x14\n\x00\x00\x0c\xc3\x08\x01\xbb\xcf\xb4\xbb\\\x00\x00\x00\x00\x80\x02 \x00\xeb\x1b\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02')  # noqa: E501
        fp = (("s", "win", "Windows", "7 or 8"), 0, False)
        self.assertEqual(p0f(pkt), fp)

    def test_linux_syn(self):
        pkt = IP(b"E\x10\x00<A0@\x00@\x06t\xdd\xc0\xa8\x01\x8c\xc0\xa8\x01\xc2\xdd\xb8\x00\x17\xda\xcf!\xd5\x00\x00\x00\x00\xa0\x02\x16\xd0q\x10\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\x00'`\xe5\x00\x00\x00\x00\x01\x03\x03\x07")  # noqa: E501
        fp = (("s", "unix", "Linux", "2.6.x"), 0, False)
        self.assertEqual(p0f(pkt), fp)

    def test_linux_syn_ack(self):
        pkt = IP(b'E\x00\x00<\x00\x00@\x008\x06N;?t\xf3a\xc0\xa8\x01\x03\x00P\xe5\xc0\xa3\xc4\x80\x9f\xe5\x94=\xab\xa0\x12\x16\xa0N\x07\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\x8d\x9d\x9d\xfa\x00\x17\x95e\x01\x03\x03\x05')  # noqa: E501
        fp = (("s", "unix", "Linux", "2.6.x"), 8, False)
        self.assertEqual(p0f(pkt), fp)

    def test_freebsd_ipv6(self):
        pkt = IPv6(hlim=64) / TCP(seq=1, window=65535, options=[("MSS", 150), ("NOP", None), ("WScale", 6), ("SAckOK", ""), ("Timestamp", (12345, 0))])  # noqa: E501
        fp = (("s", "unix", "FreeBSD", "9.x or newer"), 0, False)
        self.assertEqual(p0f(pkt), fp)
