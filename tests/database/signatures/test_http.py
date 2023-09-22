from pyp0f.database.signatures.http import SignatureHeader, _parse_headers


def test_parse_headers():
    assert _parse_headers("Host,?Cookies,Accept=[*/*],?Pragma=[no-cache]") == [
        SignatureHeader(name=b"Host", is_optional=False),
        SignatureHeader(name=b"Cookies", is_optional=True),
        SignatureHeader(name=b"Accept", is_optional=False, value=b"*/*"),
        SignatureHeader(name=b"Pragma", is_optional=True, value=b"no-cache"),
    ]
