"""
This file benchmarks the main methods `pyp0f` provides - fingerprint, impersonate.
The following results were ran on my PC using an i5 7th gen.

Performance benchmark: Load Database
Ran 1000 iterations in 9.76s
Average time for one iteration of Load Database: 9ms
-----------------------------------
Performance benchmark: MTU Fingerprint (25 Packets)
Ran 1000 iterations in 19.808s
Average time for one iteration of MTU Fingerprint (25 Packets): 19ms
-----------------------------------
Performance benchmark: TCP Fingerprint (153 Packets)
Ran 1000 iterations in 227.91s
Average time for one iteration of TCP Fingerprint (153 Packets): 227ms
-----------------------------------
Performance benchmark: HTTP Fingerprint (3 Packets)
Ran 1000 iterations in 0.15791s
Average time for one iteration of HTTP Fingerprint (3 Packets): 0ms
-----------------------------------
Performance benchmark: MTU Impersonation (25 Signatures)
Ran 1000 iterations in 4.5696s
Average time for one iteration of MTU Impersonation (25 Signatures): 4ms
-----------------------------------
Performance benchmark: TCP Impersonation (153 Signatures)
Ran 1000 iterations in 103.97s
Average time for one iteration of TCP Impersonation (153 Signatures): 103ms
"""
import time
from typing import Callable, Optional

from pyp0f.database import DATABASE
from pyp0f.database.records import MTURecord, TCPRecord
from pyp0f.fingerprint import fingerprint_http, fingerprint_mtu, fingerprint_tcp
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp
from pyp0f.net.packet import Direction
from pyp0f.net.scapy import ScapyIPv4, ScapyTCP
from tests._packets import HTTP_PACKETS

DATABASE.load()


def measure_performance(
    func: Callable, *, title: Optional[str] = None, iterations: int = 1000
) -> None:
    total_ms = 0
    total_seconds = 0

    print("-----------------------------------")
    print(f"Performance benchmark: {title}")

    for _ in range(iterations):
        start = time.perf_counter()

        func()

        end = time.perf_counter()

        total_seconds += end - start
        total_ms += int(round((end - start) * 1000))

    print(f"Ran {iterations} iterations in {total_seconds:.5}s")
    print(f"Average time for one iteration of {title}: {total_ms // iterations}ms")


def measure_load_database():
    def load_database():
        DATABASE.load()

    measure_performance(load_database, title="Load Database")


def measure_mtu_fingerprint():
    all_mtu_records = [
        (mtu_record.raw_signature, mtu_record.label.dump())
        for mtu_record in DATABASE.iter_values(MTURecord)
    ]

    all_mtu = [
        (
            impersonate_mtu(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig),
            expected_label,
        )
        for raw_sig, expected_label in all_mtu_records
    ]

    def fingerprint():
        for packet, expected_label in all_mtu:
            result = fingerprint_mtu(packet)
            assert result.match is not None
            assert result.match.label.dump() == expected_label

    measure_performance(fingerprint, title=f"MTU Fingerprint ({len(all_mtu)} Packets)")


def measure_tcp_fingerprint():
    syn_tcp_records = [
        (tcp_record.raw_signature, tcp_record.label.dump())
        for tcp_record in DATABASE.iter_values(TCPRecord, Direction.CLIENT_TO_SERVER)
        if (
            not tcp_record.label.is_generic
            # Ignore eol+n since it is not implemented
            and "eol+" not in tcp_record.raw_signature
        )
    ]

    syn_ack_tcp_records = [
        (tcp_record.raw_signature, tcp_record.label.dump())
        for tcp_record in DATABASE.iter_values(TCPRecord, Direction.SERVER_TO_CLIENT)
        if (
            not tcp_record.label.is_generic
            # Ignore eol+n since it is not implemented
            and "eol+" not in tcp_record.raw_signature
            # Mac OS X:10.x has same signature as previous FreeBSD:8.x-9.x (lines 441, 466)
            and tcp_record.raw_signature != "*:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0"
        )
    ]

    syn_impersonated_tcp = [
        (
            impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig),
            expected_label,
        )
        for raw_sig, expected_label in syn_tcp_records
    ]

    syn_ack_impersonated_tcp = [
        (
            impersonate_tcp(
                ScapyIPv4() / ScapyTCP(flags="SA", ack=6), raw_signature=raw_sig
            ),
            expected_label,
        )
        for raw_sig, expected_label in syn_ack_tcp_records
    ]

    all_impersonated_tcp = syn_impersonated_tcp + syn_ack_impersonated_tcp

    def fingerprint():
        for packet, expected_label in all_impersonated_tcp:
            result = fingerprint_tcp(packet)
            assert result.match is not None
            assert result.match.record.label.dump() == expected_label

    measure_performance(
        fingerprint, title=f"TCP Fingerprint ({len(all_impersonated_tcp)} Packets)"
    )


def measure_http_fingerprint():
    def fingerprint():
        for test_packet in HTTP_PACKETS:
            result = fingerprint_http(test_packet.payload)
            assert result.match is not None
            assert result.match.label.dump() == test_packet.expected_label

    measure_performance(
        fingerprint, title=f"HTTP Fingerprint ({len(HTTP_PACKETS)} Packets)"
    )


def measure_mtu_impersonation():
    all_mtu_sigs = [
        mtu_record.raw_signature for mtu_record in DATABASE.iter_values(MTURecord)
    ]

    def impersonate():
        for raw_sig in all_mtu_sigs:
            impersonate_mtu(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)

    measure_performance(
        impersonate, title=f"MTU Impersonation ({len(all_mtu_sigs)} Signatures)"
    )


def measure_tcp_impersonation():
    syn_tcp_sigs = [
        tcp_record.raw_signature
        for tcp_record in DATABASE.iter_values(TCPRecord, Direction.CLIENT_TO_SERVER)
        if (
            not tcp_record.label.is_generic
            # Ignore eol+n since it is not implemented
            and "eol+" not in tcp_record.raw_signature
        )
    ]

    syn_ack_tcp_sigs = [
        tcp_record.raw_signature
        for tcp_record in DATABASE.iter_values(TCPRecord, Direction.SERVER_TO_CLIENT)
        if (
            not tcp_record.label.is_generic
            # Ignore eol+n since it is not implemented
            and "eol+" not in tcp_record.raw_signature
            # Mac OS X:10.x has same signature as previous FreeBSD:8.x-9.x (lines 441, 466)
            and tcp_record.raw_signature != "*:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0"
        )
    ]

    def impersonate():
        for raw_sig in syn_tcp_sigs:
            impersonate_tcp(ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig)

        for raw_sig in syn_ack_tcp_sigs:
            impersonate_tcp(
                ScapyIPv4() / ScapyTCP(flags="SA", ack=6), raw_signature=raw_sig
            )

    measure_performance(
        impersonate,
        title=f"TCP Impersonation ({len(syn_tcp_sigs + syn_ack_tcp_sigs)} Signatures)",
    )


measure_load_database()
measure_mtu_fingerprint()
measure_tcp_fingerprint()
measure_http_fingerprint()
measure_mtu_impersonation()
measure_tcp_impersonation()
