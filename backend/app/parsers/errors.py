"""Controlled errors exposed by event ingestion and normalization boundaries."""


class WindowsEventIngestionError(ValueError):
    """Base error for invalid Windows Event XML input."""


class MalformedEventXmlError(WindowsEventIngestionError):
    """Raised when an input string is not syntactically valid XML."""


class InvalidRawEventError(WindowsEventIngestionError):
    """Raised when XML cannot form a valid raw Windows Event."""


class EventNormalizationError(ValueError):
    """Base error for event normalization failures."""


class UnsupportedEventError(EventNormalizationError):
    """Raised when no supported normalizer exists for the raw event identity."""


class InvalidNormalizedEventError(EventNormalizationError):
    """Raised when source values cannot form a valid normalized event."""
