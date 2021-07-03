MIN_TCP4 = 40  # Min size of IPv4/TCP headers
MIN_TCP6 = 60  # Min size of IPv6/TCP headers
MAX_DIST = 35  # Maximum TTL distance for non-fuzzy signature matching


class WinType:
    NORMAL = 0  # Literal value
    ANY = 1  # Wildcard
    MOD = 2  # Modulo check
    MSS = 3  # Window size MSS multiplier
    MTU = 4  # Window size MTU multiplier


class TCPFlag:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PUSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
