import pytest

from pyp0f.database import DATABASE


@pytest.fixture(scope="session", autouse=True)
def load_database():
    DATABASE.load()
