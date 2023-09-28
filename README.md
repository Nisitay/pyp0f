<h1 align="center">pyp0f</h1>
<p align="center">Native implementation of <strong>p0f v3</strong> in typed Python 3.</p>


---

**Documentation**: <a href="https://github.com/Nisitay/pyp0f/blob/master/docs/README.md" target="_blank">https://github.com/Nisitay/pyp0f/blob/master/docs/README.md</a>

**Source Code**: <a href="https://github.com/Nisitay/pyp0f" target="_blank">https://github.com/Nisitay/pyp0f</a>

---

`pyp0f` is able to accurately guess the source OS or user application of a given packet with passive fingerprinting, as well as impersonate packets so that `p0f` will think it has been sent by a specific OS.

## Motivation
- `pyp0f` is platform independent (using [Scapy](https://scapy.net)), while `p0f` can be cumbersome to run on some platforms (such as Windows).
- The implementation and concepts behind `p0f` are very sophisticated, but the tool is written in C which makes it harder to understand and extend. Performance is expected to be slower in Python, but `pyp0f` still performs well enough (see [Performance benchmarks](https://github.com/Nisitay/pyp0f/blob/master/docs/README.md#performance-benchmarks))
- `p0f` heavily depends on full packet flow details, while `pyp0f` attempts to use as little information as possible. For example, you may be able to fingerprint a SYN+ACK packet from a session without having the matching SYN packet.
- `pyp0f` aims to be highly configurable and used as a library, without limiting its effectiveness to one packet format/library, as opposed to `p0f` which runs on a seperate process and you query the results using an API.

## Installation
```console
$ pip install pyp0f
```

## Features
- Full p0f fingerprinting (MTU, TCP, HTTP)
- p0f spoofing - impersonation (MTU, TCP)
- TCP timestamps uptime detection

## In Progress
- Flow tracking
- NAT detection

## Getting Started
```python
from scapy.layers.inet import IP, TCP
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult

DATABASE.load()  # Load the fingerprints database

# MTU Fingerprinting
google_packet = IP() / TCP(options=[("MSS", 1430)])
mtu_result: MTUResult = fingerprint_mtu(google_packet)

# TCP Fingerprinting
linux_packet = IP(tos=0x10, flags=0x02, ttl=58) / TCP(
    seq=1,
    window=29200,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (177816630, 0)), ("NOP", None), ("WScale", 7)],
)
tcp_result: TCPResult = fingerprint_tcp(linux_packet)

# HTTP Fingerprinting
apache_payload = b"HTTP/1.1 200 OK\r\nDate: Fri, 10 Jun 2011 13:27:01 GMT\r\nServer: Apache\r\nLast-Modified: Thu, 09 Jun 2011 17:25:43 GMT\r\nExpires: Mon, 13 Jun 2011 17:25:43 GMT\r\nETag: 963D6BC0ED128283945AF1FB57899C9F3ABF50B3\r\nCache-Control: max-age=272921,public,no-transform,must-revalidate\r\nContent-Length: 491\r\nConnection: close\r\nContent-Type: application/ocsp-response\r\n\r\n"
http_result: HTTPResult = fingerprint_http(apache_payload)
```

## Sources
- [p0f source code](https://github.com/p0f/p0f)
- [Scapy docs & source code](https://scapy.net)

## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)
