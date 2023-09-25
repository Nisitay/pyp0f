"""
This file tests the full functionality of the impersonation modules (MTU, TCP).

A default scapy packet is impersonated for each record in the database,
and verify that fingerprinting each one results in the desired fingerprint.

Since the impersonation module randomizes many of the packet values,
the testing process is repeated many times to verify it is working.
"""
import pytest

from pyp0f.database import DATABASE
from pyp0f.database.records import MTURecord, TCPRecord
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp
from pyp0f.net.packet import Direction
from pyp0f.net.scapy import ScapyIPv4, ScapyTCP
from tests.config import (
    FULL_IMPERSONATION_TESTS_ITERATIONS,
    SKIP_FULL_IMPERSONATION_TESTS,
)


class TestFullImpersonation:
    @pytest.mark.skipif(
        SKIP_FULL_IMPERSONATION_TESTS, reason="Relatively slow, isolated module"
    )
    def test_impersonate_mtu(self):
        all_mtu_records = [
            (mtu_record.raw_signature, mtu_record.label.dump())
            for mtu_record in DATABASE.iter_values(MTURecord)
        ]

        for _ in range(FULL_IMPERSONATION_TESTS_ITERATIONS):
            for raw_sig, expected_label in all_mtu_records:
                packet = impersonate_mtu(
                    ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig
                )
                result = fingerprint_mtu(packet)
                assert result.match is not None
                assert result.match.label.dump() == expected_label

    @pytest.mark.skipif(
        SKIP_FULL_IMPERSONATION_TESTS, reason="Relatively slow, isolated module"
    )
    def test_impersonate_tcp_syn(self):
        all_tcp_records = [
            (tcp_record.raw_signature, tcp_record.label.dump())
            for tcp_record in DATABASE.iter_values(
                TCPRecord, Direction.CLIENT_TO_SERVER
            )
            if (
                not tcp_record.label.is_generic
                # Ignore eol+n since it is not implemented
                and "eol+" not in tcp_record.raw_signature
            )
        ]

        for _ in range(FULL_IMPERSONATION_TESTS_ITERATIONS):
            for raw_sig, expected_label in all_tcp_records:
                packet = impersonate_tcp(
                    ScapyIPv4() / ScapyTCP(), raw_signature=raw_sig
                )
                result = fingerprint_tcp(packet)
                assert result.match is not None
                assert result.match.record.label.dump() == expected_label

    @pytest.mark.skipif(
        SKIP_FULL_IMPERSONATION_TESTS, reason="Relatively slow, isolated module"
    )
    def test_impersonate_tcp_syn_ack(self):
        all_tcp_records = [
            (tcp_record.raw_signature, tcp_record.label.dump())
            for tcp_record in DATABASE.iter_values(
                TCPRecord, Direction.SERVER_TO_CLIENT
            )
            if (
                not tcp_record.label.is_generic
                # Ignore eol+n since it is not implemented
                and "eol+" not in tcp_record.raw_signature
                # Mac OS X:10.x has same signature as previous FreeBSD:8.x-9.x (lines 441, 466)
                and tcp_record.raw_signature
                != "*:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0"
            )
        ]

        for _ in range(FULL_IMPERSONATION_TESTS_ITERATIONS):
            for raw_sig, expected_label in all_tcp_records:
                packet = impersonate_tcp(
                    ScapyIPv4() / ScapyTCP(flags="SA", ack=6), raw_signature=raw_sig
                )
                result = fingerprint_tcp(packet)
                assert result.match is not None
                assert result.match.record.label.dump() == expected_label
