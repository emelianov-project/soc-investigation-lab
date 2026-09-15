"""Tests for the raw Windows Event XML ingestion boundary."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.models import RawWindowsEvent
from app.parsers import InvalidRawEventError, MalformedEventXmlError, parse_windows_event_xml
from pydantic import ValidationError

FIXTURE_ROOT = Path(__file__).parents[3] / "tests" / "fixtures" / "windows"
WINDOWS_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

FIXTURES = (
    (
        "security/security_4624_successful_logon.xml",
        "Microsoft-Windows-Security-Auditing",
        4624,
        "Security",
        1001,
    ),
    (
        "security/security_4625_failed_logon.xml",
        "Microsoft-Windows-Security-Auditing",
        4625,
        "Security",
        1002,
    ),
    (
        "security/security_4688_process_creation.xml",
        "Microsoft-Windows-Security-Auditing",
        4688,
        "Security",
        1003,
    ),
    (
        "sysmon/sysmon_1_process_creation.xml",
        "Microsoft-Windows-Sysmon",
        1,
        "Microsoft-Windows-Sysmon/Operational",
        2001,
    ),
    (
        "sysmon/sysmon_3_network_connection.xml",
        "Microsoft-Windows-Sysmon",
        3,
        "Microsoft-Windows-Sysmon/Operational",
        2002,
    ),
    (
        "sysmon/sysmon_11_file_create.xml",
        "Microsoft-Windows-Sysmon",
        11,
        "Microsoft-Windows-Sysmon/Operational",
        2003,
    ),
    (
        "sysmon/sysmon_22_dns_query.xml",
        "Microsoft-Windows-Sysmon",
        22,
        "Microsoft-Windows-Sysmon/Operational",
        2004,
    ),
)


def _read_fixture(relative_path: str) -> str:
    return (FIXTURE_ROOT / relative_path).read_text(encoding="utf-8")


def _event_xml(
    *,
    provider: str = '<Provider Name="Synthetic-Provider" />',
    event_id: str = "42",
    time_created: str = '<TimeCreated SystemTime="2026-01-15T10:00:00.0000000Z" />',
    channel: str = "Security",
    computer: str = "WS-01.example.com",
    record_id: str | None = "7",
    event_data: str | None = '<EventData><Data Name="UnknownField">source value</Data></EventData>',
    extra_system: str = "",
    extra_event: str = "",
) -> str:
    record_element = "" if record_id is None else f"<EventRecordID>{record_id}</EventRecordID>"
    event_data_element = "" if event_data is None else event_data
    return f"""<Event xmlns="{WINDOWS_NAMESPACE}">
  <System>
    {provider}
    <EventID>{event_id}</EventID>
    {time_created}
    <Channel>{channel}</Channel>
    <Computer>{computer}</Computer>
    {record_element}
    {extra_system}
  </System>
  {event_data_element}
  {extra_event}
</Event>"""


@pytest.mark.parametrize(
    ("relative_path", "provider", "event_id", "channel", "record_id"),
    FIXTURES,
)
def test_all_committed_fixtures_parse(
    relative_path: str,
    provider: str,
    event_id: int,
    channel: str,
    record_id: int,
) -> None:
    event = parse_windows_event_xml(_read_fixture(relative_path))

    assert event.provider == provider
    assert event.event_id == event_id
    assert event.channel == channel
    assert event.computer == "WS-01.example.com"
    assert event.record_id == record_id
    assert event.timestamp.tzinfo is UTC
    assert event.timestamp.utcoffset() == UTC.utcoffset(event.timestamp)


@pytest.mark.parametrize(
    ("relative_path", "field_name", "expected"),
    (
        ("security/security_4624_successful_logon.xml", "TargetUserName", "lab.user"),
        ("security/security_4625_failed_logon.xml", "FailureReason", "%%2313"),
        (
            "security/security_4688_process_creation.xml",
            "CommandLine",
            "cmd.exe /c echo synthetic-fixture",
        ),
        ("sysmon/sysmon_1_process_creation.xml", "Image", r"C:\Windows\System32\cmd.exe"),
        ("sysmon/sysmon_3_network_connection.xml", "DestinationIp", "203.0.113.53"),
        (
            "sysmon/sysmon_11_file_create.xml",
            "TargetFilename",
            r"C:\Users\lab.user\Documents\synthetic.txt",
        ),
        ("sysmon/sysmon_22_dns_query.xml", "QueryName", "api.example.com"),
    ),
)
def test_event_data_retains_representative_source_values(
    relative_path: str,
    field_name: str,
    expected: str,
) -> None:
    event = parse_windows_event_xml(_read_fixture(relative_path))

    assert event.event_data[field_name] == expected


def test_unknown_event_data_field_is_preserved() -> None:
    event = parse_windows_event_xml(_event_xml())

    assert event.event_data == {"UnknownField": "source value"}


def test_empty_event_data_value_is_preserved() -> None:
    event = parse_windows_event_xml(
        _event_xml(event_data='<EventData><Data Name="EmptyField" /></EventData>')
    )

    assert event.event_data == {"EmptyField": ""}


def test_absent_event_record_id_remains_none() -> None:
    event = parse_windows_event_xml(_event_xml(record_id=None))

    assert event.record_id is None


def test_absent_event_data_becomes_empty_mapping() -> None:
    event = parse_windows_event_xml(_event_xml(event_data=None))

    assert event.event_data == {}


def test_parsing_is_deterministic() -> None:
    xml = _read_fixture("security/security_4624_successful_logon.xml")

    assert parse_windows_event_xml(xml) == parse_windows_event_xml(xml)


def test_timestamp_with_offset_is_normalized_to_utc() -> None:
    event = parse_windows_event_xml(
        _event_xml(time_created='<TimeCreated SystemTime="2026-01-15T13:00:00+03:00" />')
    )

    assert event.timestamp == datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC


def test_raw_event_model_is_frozen() -> None:
    event = parse_windows_event_xml(_event_xml())

    with pytest.raises(ValidationError):
        event.provider = "Changed-Provider"


def test_raw_event_model_forbids_extra_fields() -> None:
    data = parse_windows_event_xml(_event_xml()).model_dump()
    data["unexpected"] = "not allowed"

    with pytest.raises(ValidationError):
        RawWindowsEvent.model_validate(data)


def test_malformed_xml_raises_controlled_error() -> None:
    with pytest.raises(MalformedEventXmlError):
        parse_windows_event_xml("<Event>")


@pytest.mark.parametrize(
    "xml",
    (
        "<NotEvent />",
        "<Event><System /></Event>",
        f'<Event xmlns="{WINDOWS_NAMESPACE}"><Event /></Event>',
    ),
)
def test_invalid_root_or_namespace_raises_controlled_error(xml: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


def test_missing_system_raises_controlled_error() -> None:
    xml = f'<Event xmlns="{WINDOWS_NAMESPACE}" />'

    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


def test_multiple_system_elements_raise_controlled_error() -> None:
    xml = _event_xml(extra_event="<System />")

    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


@pytest.mark.parametrize(
    "provider",
    ("", "<Provider />", '<Provider Name="   " />'),
)
def test_invalid_provider_raises_controlled_error(provider: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(_event_xml(provider=provider))


@pytest.mark.parametrize("event_id", ("", "not-an-integer", "0", "-1"))
def test_invalid_event_id_raises_controlled_error(event_id: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(_event_xml(event_id=event_id))


@pytest.mark.parametrize(
    "required_element",
    (
        "<EventID>42</EventID>",
        "<Channel>Security</Channel>",
        "<Computer>WS-01.example.com</Computer>",
    ),
)
def test_missing_required_system_element_raises_controlled_error(
    required_element: str,
) -> None:
    xml = _event_xml().replace(required_element, "")

    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


@pytest.mark.parametrize(
    "time_created",
    (
        "",
        "<TimeCreated />",
        '<TimeCreated SystemTime="   " />',
        '<TimeCreated SystemTime="not-a-timestamp" />',
        '<TimeCreated SystemTime="2026-01-15T10:00:00" />',
    ),
)
def test_invalid_timestamp_raises_controlled_error(time_created: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(_event_xml(time_created=time_created))


@pytest.mark.parametrize(("field", "value"), (("Channel", ""), ("Computer", "")))
def test_missing_required_text_raises_controlled_error(field: str, value: str) -> None:
    xml = _event_xml(channel=value) if field == "Channel" else _event_xml(computer=value)

    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


@pytest.mark.parametrize("record_id", ("", "not-an-integer", "-1"))
def test_invalid_event_record_id_raises_controlled_error(record_id: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(_event_xml(record_id=record_id))


def test_multiple_event_data_elements_raise_controlled_error() -> None:
    xml = _event_xml(extra_event="<EventData />")

    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(xml)


@pytest.mark.parametrize(
    "event_data",
    (
        "<EventData><Data>value</Data></EventData>",
        '<EventData><Data Name="   ">value</Data></EventData>',
        '<EventData><Data Name="Field">one</Data><Data Name="Field">two</Data></EventData>',
        '<EventData><Data Name="Field"><Nested /></Data></EventData>',
        "<EventData><Unexpected /></EventData>",
    ),
)
def test_invalid_event_data_raises_controlled_error(event_data: str) -> None:
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml(_event_xml(event_data=event_data))
