from scapy.modules.six.moves import range


def lparse(line, n, delimiter=":", default=""):
    """
    Parsing of 'a:b:c:d:e' lines
    """
    a = line.split(delimiter)[:n]
    for elt in a:
        yield elt
    for _ in range(n - len(a)):
        yield default


def guess_dist(ttl):
    for opt in (32, 64, 128, 255):
        if ttl <= opt:
            return opt - ttl
