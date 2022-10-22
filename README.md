# pyp0f

Native implementation of ``p0f`` v3 in typed Python 3.

``pyp0f`` is able to accurately guess the source OS or user application of a given packet with passive fingerprinting.

#### Motivation
- ``pyp0f`` is platform independent, while p0f can be cumbersome to run on some platforms (such as Windows).
- ``pyp0f`` is mainly used as a library, as opposed to p0f which runs on a seperate process and you query the results using an API.
- p0f depends on full packet flow details, while ``pyp0f`` attempts to use as little information as possible. For example, you can easily fingerprint one packet from a session without knowing the session history. 

## Installation

```shell
pip install pyp0f
```

## Features
- MTU fingerprinting
- TCP fingerprinting
- HTTP fingerprinting

## TODO
- Flow tracking
- TCP uptime detection
- p0f tool loop
- Impersonation tool
- NAT detection

## Usage
pyp0f accepts SYN, SYN+ACK and HTTP packets. If the packet is invalid for fingerprint, ``pyp0f.exceptions.PacketError`` is raised.

### Database
Before fingerprinting, make sure to load the p0f signatures database.

By default, the included (v3.09b) database will be loaded. However, you can specify a custom database path to
parse.

```python
from pyp0f.database import DATABASE

DATABASE.load()
# or DATABASE.load("path/to/database/file/p0f.fp")

print(len(DATABASE))  # 322
```

### Fingerprinting

pyp0f has 3 main functions:
```python
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
```

Each fingerprint function returns a custom result object which includes some informative fields that are typed appropriately, such as:
- The parsed packet
- The calculated packet signature
- The matched record, if any

#### Examples

```python
from scapy.layers.inet import IP

from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http

packet = IP(b'...')
mtu_result = fingerprint_mtu(packet)
tcp_result = fingerprint_tcp(packet)
http_result = fingerprint_http(packet)

print(mtu_result.match.label.name)  # Ethernet or modem
print(tcp_result.match.record.label.dump())  # s:win:Windows:7 or 8
print(http_result.match.label.dump())  # s:!:nginx:1.x
```

## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)
