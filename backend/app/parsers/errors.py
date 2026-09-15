"""Controlled errors exposed by Windows Event XML ingestion."""


class WindowsEventIngestionError(ValueError):
    """Base error for invalid Windows Event XML input."""


class MalformedEventXmlError(WindowsEventIngestionError):
    """Raised when an input string is not syntactically valid XML."""


class InvalidRawEventError(WindowsEventIngestionError):
    """Raised when XML cannot form a valid raw Windows Event."""
