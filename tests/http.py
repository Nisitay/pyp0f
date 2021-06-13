from scapy.layers.inet import IP
from scapy_p0f.p0fv3 import p0f

# HTTP request from wget client
wget_req = IP(b'E\x00\x00\xba\xcb]@\x00@\x06(d\xc0\xa8\x01\x8c\xae\x8f\xd5\xb8\xe1N\x00P\x8eP\x19\x02\xc7R\x9d\x89\x80\x18\x00.G)\x00\x00\x01\x01\x08\n\x00!\xd2_1\xc7\xbaHGET /images/layout/logo.png HTTP/1.0\r\nUser-Agent: Wget/1.12 (linux-gnu)\r\nAccept: */*\r\nHost: packetlife.net\r\nConnection: Keep-Alive\r\n\r\n')  # noqa: E501
assert p0f(wget_req)[2] == "wget"

# HTTP response from nginx server
nginx_resp = IP(b"E\x00\x05\xdc'\xde@\x00\xfb\x06\x0b\xc1\xae\x8f\xd5\xb8\xc0\xa8\x01\x8c\x00P\xe1N\xc7R\x9d\x89\x8eP\x19\x88\x80\x10\x00lS\xc4\x00\x00\x01\x01\x08\n1\xc7\xbaT\x00!\xd2_HTTP/1.1 200 OK\r\nServer: nginx/0.8.53\r\nDate: Tue, 01 Mar 2011 20:45:16 GMT\r\nContent-Type: image/png\r\nContent-Length: 21684\r\nLast-Modified: Fri, 21 Jan 2011 03:41:14 GMT\r\nConnection: keep-alive\r\nKeep-Alive: timeout=20\r\nExpires: Wed, 29 Feb 2012 20:45:16 GMT\r\nCache-Control: max-age=31536000\r\nCache-Control: public\r\nVary: Accept-Encoding\r\nAccept-Ranges: bytes\r\n\r\n")  # noqa: E501
assert p0f(nginx_resp)[2] == "nginx"