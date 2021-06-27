MIN_TCP4 = 40  # Min size of IPv4/TCP headers
MIN_TCP6 = 60  # Min size of IPv6/TCP headers
MAX_DIST = 35  # Maximum TTL distance for non-fuzzy signature matching

WIN_TYPE_NORMAL = 0  # Literal value
WIN_TYPE_ANY = 1  # Wildcard
WIN_TYPE_MOD = 2  # Modulo check
WIN_TYPE_MSS = 3  # Window size MSS multiplier
WIN_TYPE_MTU = 4  # Window size MTU multiplier
