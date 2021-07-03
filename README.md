# scapy-p0f
A native implementation of p0f v3 in Python.

scapy-p0f allows you to accurately guess the source OS or user application of a given [Scapy](https://github.com/secdev/scapy) packet with passive fingerprinting.

scapy-p0f supports Python 2.7 and Python 3 (3.4 to 3.7).

## Installation
You can install scapy-p0f by running

    $ pip install scapy-p0f

## Usage
scapy-p0f has 4 main functions: [p0f](#p0f-function), [p0f_impersonate](#p0f_impersonate-function), [prnp0f](#prnp0f-function) and [fingerprint_mtu](#fingerprint_mtu-function).

**Note:**
p0f v3 supports SYN/SYN+ACK and HTTP packets. If the given packet isn't valid for p0f, an exception is raised.

### Fingerprint Match Format
|          | TCP Match                  |  HTTP Match          | MTU Match |
| -------- | -------------------------- | -------------------- | --------- |
| Overview | `(label, distance, fuzzy)` | `(label, dishonest)` | `label`   |
| Types    | `(tuple, int, bool)`       | `(tuple, bool)`      | `str`     |

### p0f Function
The main `p0f` function is used to fingerprint the OS/user application.
The function receives a `Scapy` packet, and returns a TCP/HTTP match (or None if no match was found):
```python
from scapy.layers.inet import IP

import scapy_p0f
pkt = IP(b'E\x00\x00<\x00\x00@\x008\x06N;?t\xf3a\xc0\xa8\x01\x03\x00P\xe5\xc0\xa3\xc4\x80\x9f\xe5\x94=\xab\xa0\x12\x16\xa0N\x07\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\x8d\x9d\x9d\xfa\x00\x17\x95e\x01\x03\x03\x05')
match = scapy_p0f.p0f(pkt)  # (("s", "unix", "Linux", "2.6.x"), 8, False)
```

### p0f_impersonate Function
The `p0f_impersonate` function is able to modify a packet so that it impersonates a certain OS. 
For now, only TCP SYN/SYN+ACK packets are supported.

The function receives a packet and multiple optional arguments:

```python
def p0f_impersonate(pkt, osgenre=None, osdetails=None, signature=None, extrahops=0, mtu=1500, uptime=None):
```
- To impersonate a packet, either `osgenre` or `signature` must be specified.
- If `signature` is specified (as a string), we use the signature.
- The specified signature must follow the p0f signature format:
`ip_ver:ttl:ip_opt_len:mss:window,wscale:opt_layout:quirks:pay_class`
- If `osgenre` is specified, we randomly pick a signature with a label
that matches `osgenre` (and `osdetails`, if specified).     
**Note:** `osgenre` is case sensitive ("Linux" instead of "linux" , etc.), and `osdetails`
is a substring of a label flavor ("7", "8" and "7 or 8" will
all match the label "s:win:Windows:7 or 8").
- `extrahops` can be specified to decrease the TTL by a certain amount to simulate hops.
- `mtu` can be specified to calculate window size if the window is based on the mtu. Defaults to 1500.
- `uptime` can be specified to insert a custom value on a timestamp if the signature includes it.

#### Examples
```python
from scapy.layers.inet import IP, TCP

from scapy_p0f import p0f, p0f_impersonate
sig = "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0"  # Signature of Linux 3.11 and newer
pkt = p0f_impersonate(IP()/TCP(), signature=sig)
match = p0f(pkt)  # (("s", "unix", "Linux", "3.11 and newer"), 0, False)

pkt = p0f_impersonate(IP()/TCP(), osgenre="Windows", osdetails="7")
match = p0f(pkt)  # (("s", "win", "Windows", "7 or 8"), 0, False)
```

### prnp0f Function
The `prnp0f` function simply calls `p0f` and prints a user-friendly output, emulating the original p0f output:
```python
>>> from scapy.layers.inet import IP
>>> import scapy_p0f
>>> pkt = IP(b'E\x00\x00<\x00\x00@\x008\x06N;?t\xf3a\xc0\xa8\x01\x03\x00P\xe5\xc0\xa3\xc4\x80\x9f\xe5\x94=\xab\xa0\x12\x16\xa0N\x07\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\x8d\x9d\x9d\xfa\x00\x17\x95e\x01\x03\x03\x05')
>>> scapy_p0f.prnp0f(pkt)
.-[ 63.116.243.97:http -> 192.168.1.3:58816 (SYN+ACK) ]-
|
| Server   = 63.116.243.97:http
| OS       = Linux 2.6.x
| Distance = 8
| Raw sig  = 4:56+8:0:1460:5792,5:mss,sok,ts,nop,ws:df:0
`____
```

### fingerprint_mtu Function
The `fingerprint_mtu` function fingerprints the MTU based on the maximum segment size specified in TCP options.
The function receives a `Scapy` TCP packet, and returns a MTU match (or None if no match was found):
```python
from scapy.layers.inet import IP

import scapy_p0f
pkt = IP(b'E\x00\x00<\x00\x00@\x008\x06N;?t\xf3a\xc0\xa8\x01\x03\x00P\xe5\xc0\xa3\xc4\x80\x9f\xe5\x94=\xab\xa0\x12\x16\xa0N\x07\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\x8d\x9d\x9d\xfa\x00\x17\x95e\x01\x03\x03\x05')
match = scapy_p0f.fingerprint_mtu(pkt)  # "Ethernet or modem"
```

## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)