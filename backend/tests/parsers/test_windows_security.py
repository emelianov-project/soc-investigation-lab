"""Tests for the raw-to-normalized Windows Security event boundary."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.models import (
    AuthenticationContext,
    AuthenticationOutcome,
    EventCategory,
    EventSource,
    NormalizedEvent,
    ProcessContext,
    RawWindowsEvent,
)
from app.parsers import (
    EventNormalizationError,
    InvalidNormalizedEventError,
    InvalidRawEventError,
    MalformedEventXmlError,
    UnsupportedEventError,
    WindowsEventIngestionError,
    normalize_windows_security_event,
    parse_windows_event_xml,
)
from pydantic import ValidationError

FIXTURE_ROOT = Path(__file__).parents[3] / "tests" / "fixtures" / "windows"
AUTHENTICATION_FIELDS = frozenset(
    {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "IpPort", "WorkstationName"}
)
PROCESS_FIELDS = frozenset(
    {
        "NewProcessName",
        "NewProcessId",
        "CommandLine",
        "ProcessId",
        "ParentProcessName",
        "SubjectUserName",
    }
)


def _fixture_event(relative_path: str) -> RawWindowsEvent:
    xml = (FIXTURE_ROOT / relative_path).read_text(encoding="utf-8")
    return parse_windows_event_xml(xml)


def _raw_event(
    event_id: int = 4624,
    event_data: dict[str, str] | None = None,
    *,
    provider: str = "Microsoft-Windows-Security-Auditing",
    channel: str = "Security",
) -> RawWindowsEvent:
    return RawWindowsEvent(
        provider=provider,
        event_id=event_id,
        channel=channel,
        timestamp=datetime(2026, 1, 15, 10, 0, tzinfo=UTC),
        computer="WS-01.example.com",
        record_id=1001,
        event_data={} if event_data is None else event_data,
    )


def _assert_common_metadata(raw: RawWindowsEvent, normalized: NormalizedEvent) -> None:
    assert normalized.source == EventSource.WINDOWS_SECURITY
    assert normalized.provider == raw.provider
    assert normalized.event_id == raw.event_id
    assert normalized.channel == raw.channel
    assert normalized.timestamp == raw.timestamp
    assert normalized.timestamp.tzinfo is raw.timestamp.tzinfo
    assert normalized.computer == raw.computer
    assert normalized.record_id == raw.record_id


def _assert_source_data(
    raw: RawWindowsEvent,
    normalized: NormalizedEvent,
    consumed: frozenset[str],
) -> None:
    assert normalized.source_data == {
        name: value for name, value in raw.event_data.items() if name not in consumed
    }
    assert consumed.isdisjoint(normalized.source_data)


@pytest.mark.parametrize(
    ("relative_path", "event_id", "outcome", "user", "source_ip", "source_port"),
    (
        (
            "security/security_4624_successful_logon.xml",
            4624,
            AuthenticationOutcome.SUCCESS,
            "lab.user",
            "192.0.2.10",
            49152,
        ),
        (
            "security/security_4625_failed_logon.xml",
            4625,
            AuthenticationOutcome.FAILURE,
            "test.user",
            "198.51.100.25",
            51515,
        ),
    ),
)
def test_authentication_fixtures_normalize(
    relative_path: str,
    event_id: int,
    outcome: AuthenticationOutcome,
    user: str,
    source_ip: str,
    source_port: int,
) -> None:
    raw = _fixture_event(relative_path)
    normalized = normalize_windows_security_event(raw)

    _assert_common_metadata(raw, normalized)
    assert normalized.event_id == event_id
    assert normalized.category == EventCategory.AUTHENTICATION
    assert isinstance(normalized.context, AuthenticationContext)
    assert normalized.context.outcome == outcome
    assert normalized.context.user == user
    assert normalized.context.domain == "EXAMPLE"
    assert normalized.context.logon_type == 3
    assert str(normalized.context.source_ip) == source_ip
    assert normalized.context.source_port == source_port
    assert normalized.context.workstation == "WS-01"
    _assert_source_data(raw, normalized, AUTHENTICATION_FIELDS)
    assert normalized.source_data["SubjectUserSid"] == "S-1-5-18"
    assert normalized.source_data["SubjectLogonId"] == "0x3e7"
    assert normalized.source_data["ProcessId"] == "0x4a0"
    assert normalized.source_data["AuthenticationPackageName"] == "NTLM"


def test_failed_logon_preserves_failure_details() -> None:
    raw = _fixture_event("security/security_4625_failed_logon.xml")
    normalized = normalize_windows_security_event(raw)

    assert normalized.source_data["Status"] == "0xc000006d"
    assert normalized.source_data["FailureReason"] == "%%2313"
    assert normalized.source_data["SubStatus"] == "0xc000006a"


def test_process_fixture_normalizes() -> None:
    raw = _fixture_event("security/security_4688_process_creation.xml")
    normalized = normalize_windows_security_event(raw)

    _assert_common_metadata(raw, normalized)
    assert normalized.event_id == 4688
    assert normalized.category == EventCategory.PROCESS
    assert isinstance(normalized.context, ProcessContext)
    assert normalized.context.image == r"C:\Windows\System32\cmd.exe"
    assert normalized.context.process_id == 8000
    assert normalized.context.parent_process_id == 5000
    assert normalized.context.command_line == "cmd.exe /c echo synthetic-fixture"
    assert normalized.context.user == "lab.user"
    assert normalized.context.parent_image is None
    _assert_source_data(raw, normalized, PROCESS_FIELDS)
    assert normalized.source_data["TokenElevationType"] == "%%1936"
    assert normalized.source_data["SubjectLogonId"] == "0x123456"
    assert normalized.source_data["SubjectDomainName"] == "EXAMPLE"
    assert normalized.source_data["SubjectUserSid"] == (
        "S-1-5-21-1111111111-2222222222-3333333333-1101"
    )


@pytest.mark.parametrize("event_id", (4624, 4625))
@pytest.mark.parametrize("sentinel", (None, "", "   ", "-", " - "))
def test_optional_authentication_fields_have_no_defaults(
    event_id: int,
    sentinel: str | None,
) -> None:
    data = {} if sentinel is None else dict.fromkeys(AUTHENTICATION_FIELDS, sentinel)
    raw = _raw_event(event_id, data)
    normalized = normalize_windows_security_event(raw)

    assert isinstance(normalized.context, AuthenticationContext)
    assert normalized.context.user is None
    assert normalized.context.domain is None
    assert normalized.context.logon_type is None
    assert normalized.context.source_ip is None
    assert normalized.context.source_port is None
    assert normalized.context.workstation is None
    assert normalized.source_data == {}


@pytest.mark.parametrize("sentinel", (None, "", "   ", "-", " - "))
def test_optional_process_fields_have_no_defaults(sentinel: str | None) -> None:
    data = {"NewProcessName": r"C:\Windows\System32\cmd.exe", "NewProcessId": "8000"}
    if sentinel is not None:
        data.update(dict.fromkeys(PROCESS_FIELDS - {"NewProcessName", "NewProcessId"}, sentinel))
    normalized = normalize_windows_security_event(_raw_event(4688, data))

    assert isinstance(normalized.context, ProcessContext)
    assert normalized.context.command_line is None
    assert normalized.context.parent_process_id is None
    assert normalized.context.parent_image is None
    assert normalized.context.user is None
    assert normalized.source_data == {}


def test_authentication_text_is_stripped() -> None:
    normalized = normalize_windows_security_event(
        _raw_event(
            event_data={
                "TargetUserName": " lab.user ",
                "TargetDomainName": " EXAMPLE ",
                "WorkstationName": " WS-01 ",
            }
        )
    )

    assert isinstance(normalized.context, AuthenticationContext)
    assert normalized.context.user == "lab.user"
    assert normalized.context.domain == "EXAMPLE"
    assert normalized.context.workstation == "WS-01"


def test_process_text_is_stripped() -> None:
    normalized = normalize_windows_security_event(
        _raw_event(
            4688,
            {
                "NewProcessName": r" C:\Windows\System32\cmd.exe ",
                "NewProcessId": "8000",
                "CommandLine": " cmd.exe /c echo synthetic-fixture ",
                "ParentProcessName": r" C:\Program Files\Example\example.exe ",
                "SubjectUserName": " lab.user ",
            },
        )
    )

    assert isinstance(normalized.context, ProcessContext)
    assert normalized.context.image == r"C:\Windows\System32\cmd.exe"
    assert normalized.context.command_line == "cmd.exe /c echo synthetic-fixture"
    assert normalized.context.parent_image == r"C:\Program Files\Example\example.exe"
    assert normalized.context.user == "lab.user"


@pytest.mark.parametrize("field", ("NewProcessId", "ProcessId"))
@pytest.mark.parametrize(
    ("value", "expected"),
    (("0x1f40", 8000), ("0X1F40", 8000), ("5000", 5000), ("08", 8), (" 0x1f40 ", 8000), ("0", 0)),
)
def test_windows_process_integer_conversion(field: str, value: str, expected: int) -> None:
    data = {"NewProcessName": "cmd.exe", "NewProcessId": "8000", field: value}
    normalized = normalize_windows_security_event(_raw_event(4688, data))

    assert isinstance(normalized.context, ProcessContext)
    actual = (
        normalized.context.process_id
        if field == "NewProcessId"
        else normalized.context.parent_process_id
    )
    assert actual == expected


@pytest.mark.parametrize("event_id", (4624, 4625))
@pytest.mark.parametrize(
    ("logon_type", "source_port", "expected_logon_type", "expected_port"),
    (
        (" 03 ", " 49152 ", 3, 49152),
        ("08", "00053", 8, 53),
        ("0", "0", 0, 0),
        ("3", "65535", 3, 65535),
    ),
)
def test_authentication_decimal_integer_conversion(
    event_id: int,
    logon_type: str,
    source_port: str,
    expected_logon_type: int,
    expected_port: int,
) -> None:
    normalized = normalize_windows_security_event(
        _raw_event(event_id, {"LogonType": logon_type, "IpPort": source_port})
    )

    assert isinstance(normalized.context, AuthenticationContext)
    assert normalized.context.logon_type == expected_logon_type
    assert normalized.context.source_port == expected_port


@pytest.mark.parametrize("event_id", (4624, 4625))
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("LogonType", "not-an-integer"),
        ("LogonType", "-1"),
        ("LogonType", "0x3"),
        ("LogonType", "1.5"),
        ("IpPort", "not-an-integer"),
        ("IpPort", "-1"),
        ("IpPort", "65536"),
        ("IpPort", "0x35"),
    ),
)
def test_invalid_authentication_integers_raise_controlled_error(
    event_id: int,
    field: str,
    value: str,
) -> None:
    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_security_event(_raw_event(event_id, {field: value}))


@pytest.mark.parametrize("field", ("NewProcessId", "ProcessId"))
@pytest.mark.parametrize("value", ("not-an-integer", "-1", "-0x1", "0xinvalid", "1.5"))
def test_invalid_process_integers_raise_controlled_error(field: str, value: str) -> None:
    data = {"NewProcessName": "cmd.exe", "NewProcessId": "8000", field: value}

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_security_event(_raw_event(4688, data))


@pytest.mark.parametrize("field", ("NewProcessName", "NewProcessId"))
@pytest.mark.parametrize("value", (None, "", "   ", "-", " - "))
def test_missing_required_process_fields_raise_controlled_error(
    field: str,
    value: str | None,
) -> None:
    data = {"NewProcessName": "cmd.exe", "NewProcessId": "8000"}
    if value is None:
        del data[field]
    else:
        data[field] = value

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_security_event(_raw_event(4688, data))


@pytest.mark.parametrize("event_id", (4624, 4625))
@pytest.mark.parametrize("value", ("not-an-ip", "192.0.2.999", "192.0.2.10/24"))
def test_invalid_present_ip_raises_controlled_error(event_id: int, value: str) -> None:
    with pytest.raises(InvalidNormalizedEventError) as error:
        normalize_windows_security_event(_raw_event(event_id, {"IpAddress": value}))

    assert isinstance(error.value.__cause__, ValidationError)


@pytest.mark.parametrize("value", ("0.0.0.0", "::", "2001:db8::10", " 192.0.2.10 "))
def test_valid_ip_values_are_not_treated_as_missing(value: str) -> None:
    normalized = normalize_windows_security_event(_raw_event(event_data={"IpAddress": value}))

    assert isinstance(normalized.context, AuthenticationContext)
    assert str(normalized.context.source_ip) == value.strip()


@pytest.mark.parametrize(
    ("provider", "channel", "event_id"),
    (
        ("Synthetic-Provider", "Security", 4624),
        ("Microsoft-Windows-Security-Auditing", "Synthetic-Channel", 4624),
        ("Microsoft-Windows-Security-Auditing", "Security", 9999),
        ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 1),
        ("Microsoft-Windows-Security-Auditing ", "Security", 4624),
        ("Microsoft-Windows-Security-Auditing", "security", 4624),
    ),
)
def test_unsupported_identity_is_rejected_before_conversion(
    provider: str,
    channel: str,
    event_id: int,
) -> None:
    raw = _raw_event(
        event_id,
        {"LogonType": "invalid", "NewProcessId": "invalid"},
        provider=provider,
        channel=channel,
    )

    with pytest.raises(UnsupportedEventError):
        normalize_windows_security_event(raw)


@pytest.mark.parametrize(
    "relative_path",
    (
        "security/security_4624_successful_logon.xml",
        "security/security_4625_failed_logon.xml",
        "security/security_4688_process_creation.xml",
    ),
)
def test_unknown_source_data_is_preserved_without_mutating_raw(relative_path: str) -> None:
    fixture = _fixture_event(relative_path)
    data = dict(fixture.event_data)
    data["SyntheticUnknownField"] = "  source-shaped unknown value  "
    data["SyntheticEmptyField"] = ""
    data["SyntheticSentinelField"] = "-"
    raw = fixture.model_copy(update={"event_data": data})
    before = raw.model_dump()
    normalized = normalize_windows_security_event(raw)

    assert normalized.source_data["SyntheticUnknownField"] == "  source-shaped unknown value  "
    assert normalized.source_data["SyntheticEmptyField"] == ""
    assert normalized.source_data["SyntheticSentinelField"] == "-"
    _assert_source_data(
        raw,
        normalized,
        PROCESS_FIELDS if raw.event_id == 4688 else AUTHENTICATION_FIELDS,
    )
    assert raw.model_dump() == before
    normalized.source_data["SyntheticUnknownField"] = "changed output"
    assert raw.event_data["SyntheticUnknownField"] == "  source-shaped unknown value  "


@pytest.mark.parametrize("event_id", (4624, 4625, 4688))
@pytest.mark.parametrize("record_id", (None, 0, 1001))
def test_optional_record_id_and_timestamp_are_copied_directly(
    event_id: int,
    record_id: int | None,
) -> None:
    timestamp = datetime(2026, 1, 15, 13, 0, tzinfo=timezone(timedelta(hours=3)))
    raw = _raw_event(event_id, {"NewProcessName": "cmd.exe", "NewProcessId": "8000"})
    raw = raw.model_copy(update={"record_id": record_id, "timestamp": timestamp})

    _assert_common_metadata(raw, normalize_windows_security_event(raw))


@pytest.mark.parametrize(
    "relative_path",
    (
        "security/security_4624_successful_logon.xml",
        "security/security_4625_failed_logon.xml",
        "security/security_4688_process_creation.xml",
    ),
)
def test_normalization_is_deterministic(relative_path: str) -> None:
    raw = _fixture_event(relative_path)

    assert normalize_windows_security_event(raw) == normalize_windows_security_event(raw)


def test_normalization_errors_are_separate_from_ingestion_errors() -> None:
    assert issubclass(EventNormalizationError, ValueError)
    assert issubclass(UnsupportedEventError, EventNormalizationError)
    assert issubclass(InvalidNormalizedEventError, EventNormalizationError)
    assert not issubclass(EventNormalizationError, WindowsEventIngestionError)
    assert not issubclass(UnsupportedEventError, WindowsEventIngestionError)
    assert not issubclass(InvalidNormalizedEventError, WindowsEventIngestionError)
    assert issubclass(WindowsEventIngestionError, ValueError)
    assert issubclass(MalformedEventXmlError, WindowsEventIngestionError)
    assert issubclass(InvalidRawEventError, WindowsEventIngestionError)

    with pytest.raises(MalformedEventXmlError):
        parse_windows_event_xml("<Event>")
    with pytest.raises(InvalidRawEventError):
        parse_windows_event_xml("<NotEvent />")
