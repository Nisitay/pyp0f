import pytest

from pyp0f.exceptions import DatabaseError
from pyp0f.net.packet import Direction
from pyp0f.database.storage import RecordStorage


class TestRecordStorage:
    def test_create_list(self):
        storage = RecordStorage()
        storage.create("R")
        assert storage._records == {
            "R": []
        }

    def test_create_directional_dict(self):
        storage = RecordStorage()
        storage.create("R", Direction.CLI_TO_SRV)
        assert storage._records == {
            "R": {
                Direction.CLI_TO_SRV: []
            }
        }

    def test_create_another_direction(self):
        storage = RecordStorage()
        storage.create("R", Direction.CLI_TO_SRV)
        storage.create("R", Direction.SRV_TO_CLI)
        assert storage._records == {
            "R": {
                Direction.CLI_TO_SRV: [],
                Direction.SRV_TO_CLI: []
            }
        }

    def test_get_list(self):
        storage = RecordStorage()
        storage.create("R")
        assert storage._get("R") == []

    def test_get_list_by_direction(self):
        storage = RecordStorage()
        storage.create("R", Direction.CLI_TO_SRV)
        assert storage._get("R", Direction.CLI_TO_SRV) == []

    def test_get_record_type_err(self):
        with pytest.raises(DatabaseError):
            RecordStorage()._get("R")

    def test_get_list_ignores_direction(self):
        storage = RecordStorage()
        storage.create("R")
        assert storage._get("R", Direction.CLI_TO_SRV) == []

    def test_get_list_by_direction_err(self):
        storage = RecordStorage()
        storage.create("R", Direction.CLI_TO_SRV)

        with pytest.raises(DatabaseError):
            storage._get("R")

        with pytest.raises(DatabaseError):
            storage._get("R", Direction.SRV_TO_CLI)

    def test_len(self):
        storage = RecordStorage({
            "R1": [1, 2, 3],
            "R2": [4, 5],
            "R3": {
                Direction.CLI_TO_SRV: [6, 7, 8]
            },
            "R4": {
                Direction.CLI_TO_SRV: [9, 10, 11],
                Direction.SRV_TO_CLI: [12, 13],
            },
        })
        assert len(storage) == 13

    def test_safe_iter(self):
        storage = RecordStorage()
        for _ in storage("R"):
            pass
