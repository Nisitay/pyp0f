import pytest
from pathlib import Path

from pyp0f.utils.path import always_path


def test_always_path():
    p = Path("/path")
    assert always_path(p) is p
    assert always_path("/path") == Path("/path")

    with pytest.raises(TypeError):
        always_path(6)
