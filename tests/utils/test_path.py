from pathlib import Path

import pytest

from pyp0f.utils.path import always_path


def test_always_path():
    path = Path("/path")
    assert always_path(path) is path
    assert always_path("/path") == Path("/path")

    with pytest.raises(TypeError):
        always_path(6)  # type: ignore
