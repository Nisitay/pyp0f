from scapy.packet import Raw

from pyp0f.impersonate import impersonate_tcp
from pyp0f.net.scapy import ScapyIPv4, ScapyTCP


class TestImpersonateTCP:
    def test_win_type_mod(self):
        raw_sig = "4:64:0:1460:%8192,0:mss,nop,ws::0"
        packet = impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)
        assert packet[ScapyTCP].window % 8192 == 0

    def test_win_type_mss(self):
        raw_sig = "4:64:0:1024:mss*4,0:mss::0"
        packet = impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)
        assert packet[ScapyTCP].window // 4 == 1024

    def test_tcp_quirks1(self):
        raw_sig = "4:64:0:1460:8192,0:mss:seq-,ack-,pushf+,urgf+:0"
        packet = impersonate_tcp(
            ScapyIPv4() / ScapyTCP(seq=1, ack=1), raw_signature=raw_sig
        )
        tcp = packet[ScapyTCP]
        assert tcp.seq == 0
        assert tcp.ack == 0
        assert tcp.flags.A
        assert tcp.flags.P
        assert tcp.flags.U

    def test_tcp_quirks2(self):
        raw_sig = "4:64:0:1460:8192,0:mss:ack+,uptr+:0"
        packet = impersonate_tcp(
            ScapyIPv4() / ScapyTCP(ack=0, flags="SAU"), raw_signature=raw_sig
        )
        tcp = packet[ScapyTCP]
        assert tcp.ack != 0
        assert tcp.urgptr != 0
        assert not tcp.flags.U
        assert not tcp.flags.A

    def test_ts_quirks(self):
        raw_sig = "4:64:0:1460:8192,0:mss,ts:ts1-,ts2+:0"
        packet = impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)
        ts1, ts2 = packet[ScapyTCP].options[1][1]
        assert ts1 == 0
        assert ts2 != 0

    def test_use_valid_hints(self):
        raw_sig = "4:64:0:*:8192,*:mss,ws,ts::0"
        options = [("MSS", 1400), ("WScale", 3), ("Timestamp", (97256, 0))]
        packet = impersonate_tcp(
            ScapyIPv4() / ScapyTCP(options=options), raw_signature=raw_sig
        )
        assert packet[ScapyTCP].options == options

    def test_invalid_hints(self):
        raw_sig = "*:64:0:1000:8192,5:mss,ws::0"
        options = [("MSS", 1400), ("WScale", 3)]
        packet = impersonate_tcp(
            ScapyIPv4() / ScapyTCP(options=options), raw_signature=raw_sig
        )
        impersonated_options = dict(packet[ScapyTCP].options)
        assert impersonated_options.get("MSS") == 1000
        assert impersonated_options.get("WScale") == 5

    def test_payload_class_add(self):
        raw_sig = "4:64:0:1460:8192,0:mss::+"
        packet = impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)
        assert Raw in packet

    def test_payload_class_remove(self):
        raw_sig = "4:64:0:1460:8192,0:mss::0"
        packet = impersonate_tcp(
            ScapyIPv4() / ScapyTCP() / "abcd", raw_signature=raw_sig
        )
        assert Raw not in packet
