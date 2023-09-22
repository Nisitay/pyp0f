import pytest

from pyp0f.database.records import HTTPRecord, MTURecord, TCPRecord
from pyp0f.database.records_database import RecordsDatabase
from pyp0f.exceptions import DatabaseError
from pyp0f.net.packet import Direction


class TestRecordsDatabase:
    def test_create_values_list(self):
        records = RecordsDatabase()
        records.create(MTURecord)
        assert records._map == {MTURecord: []}

    def test_create_values_by_direction(self):
        records = RecordsDatabase()
        records.create(MTURecord, Direction.CLIENT_TO_SERVER)
        assert records._map == {MTURecord: {Direction.CLIENT_TO_SERVER: []}}

    def test_create_multiple_directions(self):
        records = RecordsDatabase()
        records.create(MTURecord, Direction.CLIENT_TO_SERVER)
        records.create(MTURecord, Direction.SERVER_TO_CLIENT)
        assert records._map == {
            MTURecord: {Direction.CLIENT_TO_SERVER: [], Direction.SERVER_TO_CLIENT: []}
        }

    def test_get_values_list(self):
        records = RecordsDatabase()
        records.create(MTURecord)
        assert records._get(MTURecord) == []

    def test_get_values_by_direction(self):
        records = RecordsDatabase()
        records.create(MTURecord, Direction.CLIENT_TO_SERVER)
        assert records._get(MTURecord, Direction.CLIENT_TO_SERVER) == []

    def test_get_values_ignores_direction(self):
        records = RecordsDatabase()
        records.create(MTURecord)
        assert records._get(MTURecord, Direction.CLIENT_TO_SERVER) == []

    def test_get_key_error(self):
        with pytest.raises(DatabaseError):
            RecordsDatabase()._get(MTURecord)

    def test_get_values_by_direction_error(self):
        records = RecordsDatabase()
        records.create(MTURecord, Direction.CLIENT_TO_SERVER)

        with pytest.raises(DatabaseError):
            records._get(MTURecord)

        with pytest.raises(DatabaseError):
            records._get(MTURecord, Direction.SERVER_TO_CLIENT)

    def test_iter_values(self):
        records = RecordsDatabase()
        for _ in records.iter_values(MTURecord):
            pass

    def test_len(self):
        records = RecordsDatabase(
            {
                MTURecord: [1, 2, 3],
                TCPRecord: {Direction.CLIENT_TO_SERVER: [4, 5, 6]},
                HTTPRecord: {
                    Direction.CLIENT_TO_SERVER: [7, 8],
                    Direction.SERVER_TO_CLIENT: [9, 10],
                },
            }  # type: ignore
        )
        assert len(records) == 10
