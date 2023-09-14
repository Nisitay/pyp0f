class P0fError(Exception):
    """
    Generic p0f error.
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

    def __init__(self, message: str, line_no: int):
        super().__init__(f"Error in line {line_no}: {message}")
        self.line_no = line_no
