"""Explicit registry for supported raw-event normalization boundaries."""

from collections.abc import Callable, Mapping
from types import MappingProxyType

from app.models import NormalizedEvent, RawWindowsEvent

from .errors import UnsupportedEventError
from .sysmon import normalize_sysmon_event
from .windows_security import normalize_windows_security_event

type EventIdentity = tuple[str, int]
type EventNormalizer = Callable[[RawWindowsEvent], NormalizedEvent]

WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

EVENT_NORMALIZER_REGISTRY: Mapping[EventIdentity, EventNormalizer] = MappingProxyType(
    {
        (WINDOWS_SECURITY_PROVIDER, 4624): normalize_windows_security_event,
        (WINDOWS_SECURITY_PROVIDER, 4625): normalize_windows_security_event,
        (WINDOWS_SECURITY_PROVIDER, 4688): normalize_windows_security_event,
        (SYSMON_PROVIDER, 1): normalize_sysmon_event,
        (SYSMON_PROVIDER, 3): normalize_sysmon_event,
        (SYSMON_PROVIDER, 11): normalize_sysmon_event,
        (SYSMON_PROVIDER, 22): normalize_sysmon_event,
    }
)

_SUPPORTED_PROVIDERS = frozenset(provider for provider, _ in EVENT_NORMALIZER_REGISTRY)


def get_event_normalizer(raw: RawWindowsEvent) -> EventNormalizer:
    """Return the registered normalizer for a raw event's provider and event ID."""
    normalizer = EVENT_NORMALIZER_REGISTRY.get((raw.provider, raw.event_id))
    if normalizer is not None:
        return normalizer
    if raw.provider not in _SUPPORTED_PROVIDERS:
        raise UnsupportedEventError(f"unsupported event provider: {raw.provider!r}")
    raise UnsupportedEventError(
        f"unsupported event ID {raw.event_id} for provider {raw.provider!r}"
    )
