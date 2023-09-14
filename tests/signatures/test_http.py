from pyp0f.net.http.headers import SigHeader
from pyp0f.signatures.http import _parse_headers


def test_parse_headers():
    assert _parse_headers("Host,?Cookies,Accept=[*/*],?Pragma=[no-cache]") == [
        SigHeader(name=b"Host", is_optional=False),
        SigHeader(name=b"Cookies", is_optional=True),
        SigHeader(name=b"Accept", is_optional=False, value=b"*/*"),
        SigHeader(name=b"Pragma", is_optional=True, value=b"no-cache"),
    ]
