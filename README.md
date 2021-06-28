# scapy-p0f
A native implementetion of p0f v3 in Python.

scapy-p0f allows you to accurately guess the source OS or user application of a given [Scapy](https://github.com/secdev/scapy) packet with passive fingerprinting.

## Usage
scapy-p0f has 3 main functions: [p0f](#p0f-function), [prnp0f](#prnp0f-function) and [fingerprint_mtu](#fingerprint_mtu-function)

**Note:**
p0f v3 supports SYN/SYN+ACK and HTTP packets. If the given packet isn't valid for p0f, an exception is raised.

### Fingerprint Match Format

|          | TCP Match                  |  HTTP Match          | MTU Match |
|--------- | -------------------------- | -------------------- | --------- |
| Overview | `(label, distance, fuzzy)` | `(label, dishonest)` | `label`   |
| Types    | `(tuple, int, bool)`       | `(tuple, bool)`      | `str`     |


### p0f Function
The main `p0f` function is used to fingerprint the OS/user application.
The function receives a `Scapy` packet, and returns a TCP/HTTP match (or None if no match was found):
```python
>>> import scapy_p0f
>>> scapy_p0f.p0f(pkt)
(("s", "unix", "Linux", "2.6.x"), 8, False)
```

### prnp0f Function
The `prnp0f` function simply calls `p0f` and returns a user-friendly output, emulating the original p0f output:
```python
>>> import scapy_p0f
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
>>> import scapy_p0f
>>> scapy_p0f.fingerprint_mtu(pkt)
"Ethernet or modem"
```



## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)
# scapy-p0f
A native implementetion of p0f v3 in Python.

scapy-p0f allows you to accurately guess the source OS or user application of a given [Scapy](https://github.com/secdev/scapy) packet with passive fingerprinting.

## Usage
scapy-p0f has 3 main functions: [p0f](#p0f-function), [prnp0f](#prnp0f-function) and [fingerprint_mtu](#fingerprint_mtu-function)

**Note:**
p0f v3 supports SYN/SYN+ACK and HTTP packets. If the given packet isn't valid for p0f, an exception is raised.

### Fingerprint Match Format

|          | TCP Match                  |  HTTP Match          | MTU Match |
|--------- | -------------------------- | -------------------- | --------- |
| Overview | `(label, distance, fuzzy)` | `(label, dishonest)` | `label`   |
| Types    | `(tuple, int, bool)`       | `(tuple, bool)`      | `str`     |


### p0f Function
The main `p0f` function is used to fingerprint the OS/user application.
The function receives a `Scapy` packet, and returns a TCP/HTTP match (or None if no match was found):
```python
>>> import scapy_p0f
>>> scapy_p0f.p0f(pkt)
(("s", "unix", "Linux", "2.6.x"), 8, False)
```

### prnp0f Function
The `prnp0f` function simply calls `p0f` and returns a user-friendly output, emulating the original p0f output:
```python
>>> import scapy_p0f
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
>>> import scapy_p0f
>>> scapy_p0f.fingerprint_mtu(pkt)
"Ethernet or modem"
```



## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)
