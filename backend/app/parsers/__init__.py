"""Public Windows Event ingestion and source-specific normalization APIs."""

from .errors import (
    EventNormalizationError,
    InvalidNormalizedEventError,
    InvalidRawEventError,
    MalformedEventXmlError,
    UnsupportedEventError,
    WindowsEventIngestionError,
)
from .pipeline import normalize_windows_event_xml
from .registry import EVENT_NORMALIZER_REGISTRY, get_event_normalizer
from .sysmon import normalize_sysmon_event
from .windows_event import parse_windows_event_xml
from .windows_security import normalize_windows_security_event

__all__ = (
    "EventNormalizationError",
    "EVENT_NORMALIZER_REGISTRY",
    "InvalidNormalizedEventError",
    "InvalidRawEventError",
    "MalformedEventXmlError",
    "UnsupportedEventError",
    "WindowsEventIngestionError",
    "get_event_normalizer",
    "normalize_sysmon_event",
    "normalize_windows_event_xml",
    "normalize_windows_security_event",
    "parse_windows_event_xml",
)
