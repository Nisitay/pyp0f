import unittest
from scapy.layers.inet import IP, TCP

from scapy_p0f.p0fv3 import p0f_impersonate


class Test_p0f_Impersonate(unittest.TestCase):
    def test_win_type_mod(self):
        sig = "4:64:0:1460:%8192,0:mss,nop,ws::0"
        pkt = p0f_impersonate(IP()/TCP(), signature=sig)
        self.assertEqual(pkt[TCP].window % 8192, 0)

    def test_win_type_mss(self):
        sig = "4:64:0:1024:mss*4,0:mss::0"
        pkt = p0f_impersonate(IP()/TCP(), signature=sig)
        self.assertEqual(pkt[TCP].window // 4, 1024)

    def test_tcp_quirks1(self):
        sig = "4:64:0:1460:8192,0:mss:seq-,ack-,pushf+,urgf+:0"
        pkt = p0f_impersonate(IP()/TCP(seq=1, ack=1), signature=sig)
        tcp = pkt[TCP]
        self.assertEqual(tcp.seq, 0)
        self.assertEqual(tcp.ack, 0)
        self.assertTrue(tcp.flags.A)
        self.assertTrue(tcp.flags.P)
        self.assertTrue(tcp.flags.U)

    def test_tcp_quirks2(self):
        sig = "4:64:0:1460:8192,0:mss:ack+,uptr+:0"
        pkt = p0f_impersonate(IP()/TCP(ack=0, flags="SAU"), signature=sig)
        tcp = pkt[TCP]
        self.assertNotEqual(tcp.ack, 0)
        self.assertNotEqual(tcp.urgptr, 0)
        self.assertFalse(tcp.flags.U)
        self.assertFalse(tcp.flags.A)

    def test_ts_quirks(self):
        sig = "4:64:0:1460:8192,0:mss,ts:ts1-,ts2+:0"
        pkt = p0f_impersonate(IP()/TCP(), signature=sig)
        ts1, ts2 = pkt[TCP].options[1][1]
        self.assertEqual(ts1, 0)
        self.assertNotEqual(ts2, 0)

    def test_use_hints(self):
        sig = "4:64:0:*:8192,*:mss,ws,ts::0"
        opts = [("MSS", 1400), ("WScale", 3), ("Timestamp", (97256, 0))]
        pkt = p0f_impersonate(IP()/TCP(options=opts), signature=sig)
        self.assertEqual(pkt[TCP].options, opts)

    def test_invalid_hints(self):
        sig = "*:64:0:1000:8192,5:mss,ws::0"
        opts = [("MSS", 1400), ("WScale", 3)]
        pkt = p0f_impersonate(IP()/TCP(options=opts), signature=sig)
        self.assertEqual(pkt[TCP].options[0][1], 1000)
        self.assertEqual(pkt[TCP].options[1][1], 5)

    def test_pay_class_add(self):
        sig = "4:64:0:1460:8192,0:mss::+"
        pkt = p0f_impersonate(IP()/TCP(), signature=sig)
        self.assertTrue(pkt.haslayer("Raw"))

    def test_pay_class_remove(self):
        sig = "4:64:0:1460:8192,0:mss::0"
        pkt = p0f_impersonate(IP()/TCP()/"abcd", signature=sig)
        self.assertFalse(pkt.haslayer("Raw"))
