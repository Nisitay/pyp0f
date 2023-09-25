class P0fError(Exception):
    """
    Base class for all exceptions thrown by pyp0f.
    """


class PacketError(P0fError):
    """
    Packet is invalid.
    """


class DatabaseError(P0fError):
    """
    Database error.
    """


class FieldError(DatabaseError):
    """
    Invalid value in the database.
    """


class ParsingError(FieldError):
    """
    Error while parsing the database.
    Includes the matching line number that the error relates to.
    """

    def __init__(self, message: str, line_number: int):
        super().__init__(f"Error in line {line_number}: {message}")
        self.line_number = line_number
