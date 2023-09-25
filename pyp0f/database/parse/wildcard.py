from typing import Union

# Wildcard for numeric fields
WILDCARD = -1
_WILDCARD_FIELD = "*"


def is_wildcard(value: Union[int, str]) -> bool:
    return value == WILDCARD or value == _WILDCARD_FIELD
