import os
from pathlib import Path
from typing import Union

PathLike = Union[str, "os.PathLike[str]"]

# /pyp0f/
ROOT_DIR = Path(__file__).parent.parent


def always_path(path: PathLike) -> Path:
    """
    Ensure the given path is a ``pathlib.Path`` object.

    Args:
        path: Path-like object

    Raises:
        TypeError: Invalid path type

    Returns:
        Path as a ``pathlib.Path``
    """
    if isinstance(path, Path):
        return path
    elif not isinstance(path, (str, os.PathLike)):
        raise TypeError(f"Expected str or os.PathLike, but got {type(path).__name__}.")
    return Path(path)
