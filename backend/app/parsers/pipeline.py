"""Stable orchestration entry point for Windows Event XML normalization."""

from app.models import NormalizedEvent

from .registry import get_event_normalizer
from .windows_event import parse_windows_event_xml


def normalize_windows_event_xml(xml: str) -> NormalizedEvent:
    """Ingest one Windows Event XML record and dispatch its raw event for normalization."""
    raw = parse_windows_event_xml(xml)
    normalizer = get_event_normalizer(raw)
    return normalizer(raw)
