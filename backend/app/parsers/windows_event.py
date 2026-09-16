"""Ingest namespaced Windows Event XML into a raw domain model."""

from datetime import UTC, datetime
from xml.etree import ElementTree

from pydantic import ValidationError

from app.models import RawWindowsEvent

from .errors import InvalidRawEventError, MalformedEventXmlError

WINDOWS_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
EVENT_TAG = f"{{{WINDOWS_EVENT_NAMESPACE}}}Event"
SYSTEM_TAG = f"{{{WINDOWS_EVENT_NAMESPACE}}}System"
EVENT_DATA_TAG = f"{{{WINDOWS_EVENT_NAMESPACE}}}EventData"
DATA_TAG = f"{{{WINDOWS_EVENT_NAMESPACE}}}Data"


def _children_with_tag(parent: ElementTree.Element, tag: str) -> list[ElementTree.Element]:
    return [child for child in parent if child.tag == tag]


def _required_single_child(
    parent: ElementTree.Element,
    tag: str,
    field_name: str,
) -> ElementTree.Element:
    matches = _children_with_tag(parent, tag)
    if len(matches) != 1:
        raise InvalidRawEventError(f"expected exactly one {field_name}")
    return matches[0]


def _required_text(
    parent: ElementTree.Element,
    local_name: str,
    field_name: str,
) -> str:
    element = _required_single_child(
        parent,
        f"{{{WINDOWS_EVENT_NAMESPACE}}}{local_name}",
        field_name,
    )
    value = (element.text or "").strip()
    if not value:
        raise InvalidRawEventError(f"{field_name} must not be blank")
    return value


def _parse_integer(value: str, field_name: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise InvalidRawEventError(f"{field_name} must be an integer") from exc


def _parse_timestamp(value: str) -> datetime:
    iso_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(iso_value)
    except ValueError as exc:
        raise InvalidRawEventError("SystemTime must be a valid datetime") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise InvalidRawEventError("SystemTime must include a timezone")
    return timestamp.astimezone(UTC)


def _parse_record_id(system: ElementTree.Element) -> int | None:
    elements = _children_with_tag(
        system,
        f"{{{WINDOWS_EVENT_NAMESPACE}}}EventRecordID",
    )
    if not elements:
        return None
    if len(elements) != 1:
        raise InvalidRawEventError("expected at most one EventRecordID")
    value = (elements[0].text or "").strip()
    if not value:
        raise InvalidRawEventError("EventRecordID must not be blank")
    return _parse_integer(value, "EventRecordID")


def _parse_event_data(root: ElementTree.Element) -> dict[str, str]:
    elements = _children_with_tag(root, EVENT_DATA_TAG)
    if not elements:
        return {}
    if len(elements) != 1:
        raise InvalidRawEventError("expected at most one EventData")

    event_data: dict[str, str] = {}
    for data_element in elements[0]:
        if data_element.tag != DATA_TAG:
            raise InvalidRawEventError("EventData may contain only Data elements")
        if len(data_element):
            raise InvalidRawEventError("Data elements must not contain nested XML")
        name = data_element.get("Name")
        if name is None or not name.strip():
            raise InvalidRawEventError("Data Name must not be missing or blank")
        if name in event_data:
            raise InvalidRawEventError(f"duplicate EventData name: {name}")
        event_data[name] = data_element.text or ""
    return event_data


def parse_windows_event_xml(xml: str) -> RawWindowsEvent:
    """Parse exactly one namespaced Windows Event into raw typed metadata."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise MalformedEventXmlError("malformed Windows Event XML") from exc

    if root.tag != EVENT_TAG or sum(element.tag == EVENT_TAG for element in root.iter()) != 1:
        raise InvalidRawEventError("root must be exactly one namespaced Windows Event")

    system = _required_single_child(root, SYSTEM_TAG, "System")
    provider_element = _required_single_child(
        system,
        f"{{{WINDOWS_EVENT_NAMESPACE}}}Provider",
        "Provider",
    )
    provider = provider_element.get("Name")
    if provider is None or not provider.strip():
        raise InvalidRawEventError("Provider Name must not be missing or blank")

    event_id = _parse_integer(_required_text(system, "EventID", "EventID"), "EventID")
    time_created = _required_single_child(
        system,
        f"{{{WINDOWS_EVENT_NAMESPACE}}}TimeCreated",
        "TimeCreated",
    )
    system_time = time_created.get("SystemTime")
    if system_time is None or not system_time.strip():
        raise InvalidRawEventError("TimeCreated SystemTime must not be missing or blank")

    try:
        return RawWindowsEvent(
            provider=provider.strip(),
            event_id=event_id,
            channel=_required_text(system, "Channel", "Channel"),
            timestamp=_parse_timestamp(system_time.strip()),
            computer=_required_text(system, "Computer", "Computer"),
            record_id=_parse_record_id(system),
            event_data=_parse_event_data(root),
        )
    except ValidationError as exc:
        raise InvalidRawEventError("invalid raw Windows Event metadata") from exc
