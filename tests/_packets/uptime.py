"""
These packets come from a single capture, from the same host.
We save the time difference between the captures of the first packet and the other for
simulation in tests.
"""
from .parse import from_hex

SYN_TIMESTAMP = from_hex(
    "4500003ca8cf400040069d6bc0a801033f74f361e5c00050e5943daa00000000a00216d09de20000020405b40402080a001795650000000001030307"
)

ACK_TIMESTAMP = from_hex(
    "45000034a8e2400040069d60c0a801033f74f361e5c00050e5943f77a3c4dfe680100154309800000101080a001795728d9d9e60"
)

TIMESTAMP_MS_DIFF = 130
