from dataclasses import dataclass


@dataclass
class HTTPTestPacket:
    expected_label: str
    payload: bytes


WGET = HTTPTestPacket(
    expected_label="s:!:wget:",
    payload=b"GET /images/layout/logo.png HTTP/1.0\r\nUser-Agent: Wget/1.12 (linux-gnu)\r\nAccept: */*\r\nHost: packetlife.net\r\nConnection: Keep-Alive\r\n\r\n",
)

NGINX = HTTPTestPacket(
    expected_label="s:!:nginx:1.x",
    payload=b"HTTP/1.1 200 OK\r\nServer: nginx/0.8.53\r\nDate: Tue, 01 Mar 2011 20:45:16 GMT\r\nContent-Type: image/png\r\nContent-Length: 21684\r\nLast-Modified: Fri, 21 Jan 2011 03:41:14 GMT\r\nConnection: keep-alive\r\nKeep-Alive: timeout=20\r\nExpires: Wed, 29 Feb 2012 20:45:16 GMT\r\nCache-Control: max-age=31536000\r\nCache-Control: public\r\nVary: Accept-Encoding\r\nAccept-Ranges: bytes\r\n\r\n",
)

APACHE = HTTPTestPacket(
    expected_label="s:!:Apache:2.x",
    payload=b"HTTP/1.1 200 OK\r\nDate: Fri, 10 Jun 2011 13:27:01 GMT\r\nServer: Apache\r\nLast-Modified: Thu, 09 Jun 2011 17:25:43 GMT\r\nExpires: Mon, 13 Jun 2011 17:25:43 GMT\r\nETag: 963D6BC0ED128283945AF1FB57899C9F3ABF50B3\r\nCache-Control: max-age=272921,public,no-transform,must-revalidate\r\nContent-Length: 491\r\nConnection: close\r\nContent-Type: application/ocsp-response\r\n\r\n",
)
