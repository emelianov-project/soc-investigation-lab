"""Tests for the isolated raw-to-normalized Sysmon boundary."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.models import (
    DnsContext,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    NormalizedEvent,
    ProcessContext,
    RawWindowsEvent,
)
from app.parsers import (
    EventNormalizationError,
    InvalidNormalizedEventError,
    UnsupportedEventError,
    normalize_sysmon_event,
    parse_windows_event_xml,
)
from pydantic import ValidationError

FIXTURE_ROOT = Path(__file__).parents[3] / "tests" / "fixtures" / "windows" / "sysmon"
FIXTURES = {
    1: "sysmon_1_process_creation.xml",
    3: "sysmon_3_network_connection.xml",
    11: "sysmon_11_file_create.xml",
    22: "sysmon_22_dns_query.xml",
}
CONSUMED_FIELDS = {
    1: frozenset({"Image", "ProcessId", "CommandLine", "ParentProcessId", "ParentImage", "User"}),
    3: frozenset(
        {
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "Protocol",
            "ProcessId",
            "Image",
        }
    ),
    11: frozenset({"TargetFilename", "ProcessId", "Image"}),
    22: frozenset({"QueryName", "QueryStatus", "QueryResults", "ProcessId", "Image"}),
}
MINIMAL_DATA = {
    1: {"Image": "cmd.exe", "ProcessId": "8000"},
    3: {
        "SourceIp": "192.0.2.10",
        "SourcePort": "53000",
        "DestinationIp": "203.0.113.53",
        "DestinationPort": "53",
    },
    11: {"TargetFilename": r"C:\Users\lab.user\Documents\synthetic.txt"},
    22: {"QueryName": "api.example.com"},
}
OPTIONAL_FIELDS = (
    (1, "CommandLine", "command_line"),
    (1, "ParentProcessId", "parent_process_id"),
    (1, "ParentImage", "parent_image"),
    (1, "User", "user"),
    (3, "Protocol", "protocol"),
    (3, "ProcessId", "process_id"),
    (3, "Image", "process_image"),
    (11, "ProcessId", "process_id"),
    (11, "Image", "process_image"),
    (22, "QueryStatus", "query_status"),
    (22, "QueryResults", "query_results"),
    (22, "ProcessId", "process_id"),
    (22, "Image", "process_image"),
)
PROCESS_ID_FIELDS = (
    (1, "ProcessId"),
    (1, "ParentProcessId"),
    (3, "ProcessId"),
    (11, "ProcessId"),
    (22, "ProcessId"),
)


def _fixture_event(event_id: int) -> RawWindowsEvent:
    return parse_windows_event_xml((FIXTURE_ROOT / FIXTURES[event_id]).read_text(encoding="utf-8"))


def _raw_event(event_id: int, data: dict[str, str] | None = None) -> RawWindowsEvent:
    return RawWindowsEvent(
        provider="Microsoft-Windows-Sysmon",
        event_id=event_id,
        channel="Microsoft-Windows-Sysmon/Operational",
        timestamp=datetime(2026, 1, 15, 10, 0, tzinfo=UTC),
        computer="WS-01.example.com",
        record_id=2001,
        event_data=MINIMAL_DATA[event_id] if data is None else data,
    )


def _assert_common_metadata(raw: RawWindowsEvent, normalized: NormalizedEvent) -> None:
    assert normalized.source == EventSource.SYSMON
    assert normalized.provider == raw.provider
    assert normalized.event_id == raw.event_id
    assert normalized.channel == raw.channel
    assert normalized.timestamp == raw.timestamp
    assert normalized.timestamp.tzinfo is raw.timestamp.tzinfo
    assert normalized.computer == raw.computer
    assert normalized.record_id == raw.record_id


def _assert_source_data(raw: RawWindowsEvent, normalized: NormalizedEvent) -> None:
    consumed = CONSUMED_FIELDS[raw.event_id]
    assert normalized.source_data == {
        name: value for name, value in raw.event_data.items() if name not in consumed
    }
    assert consumed.isdisjoint(normalized.source_data)


@pytest.mark.parametrize(
    ("event_id", "category", "context_type", "expected"),
    (
        (
            1,
            EventCategory.PROCESS,
            ProcessContext,
            {
                "image": r"C:\Windows\System32\cmd.exe",
                "process_id": 8000,
                "command_line": "cmd.exe /c echo synthetic-fixture",
                "parent_process_id": 5000,
                "parent_image": r"C:\Windows\explorer.exe",
                "user": r"EXAMPLE\lab.user",
            },
        ),
        (
            3,
            EventCategory.NETWORK,
            NetworkContext,
            {
                "source_ip": "192.0.2.10",
                "source_port": 53000,
                "destination_ip": "203.0.113.53",
                "destination_port": 53,
                "protocol": "udp",
                "process_id": 8100,
                "process_image": r"C:\Program Files\Example\example.exe",
            },
        ),
        (
            11,
            EventCategory.FILE,
            FileContext,
            {
                "target_path": r"C:\Users\lab.user\Documents\synthetic.txt",
                "process_id": 8200,
                "process_image": r"C:\Program Files\Example\example.exe",
            },
        ),
        (
            22,
            EventCategory.DNS,
            DnsContext,
            {
                "query_name": "api.example.com",
                "query_status": "0",
                "query_results": "203.0.113.53",
                "process_id": 8300,
                "process_image": r"C:\Program Files\Example\example.exe",
            },
        ),
    ),
)
def test_existing_fixtures_normalize(
    event_id: int,
    category: EventCategory,
    context_type: type[ProcessContext | NetworkContext | FileContext | DnsContext],
    expected: dict[str, str | int | None],
) -> None:
    raw = _fixture_event(event_id)
    normalized = normalize_sysmon_event(raw)

    _assert_common_metadata(raw, normalized)
    assert normalized.category == category
    assert isinstance(normalized.context, context_type)
    assert normalized.context.model_dump(mode="json") == expected
    _assert_source_data(raw, normalized)


@pytest.mark.parametrize("event_id", FIXTURES)
def test_source_data_is_preserved_verbatim_without_mutating_raw(event_id: int) -> None:
    fixture = _fixture_event(event_id)
    data = dict(fixture.event_data)
    data.update(
        {"UnknownField": "  unchanged source text  ", "EmptyField": "", "SentinelField": "-"}
    )
    raw = fixture.model_copy(update={"event_data": data})
    before = raw.model_dump()
    normalized = normalize_sysmon_event(raw)

    _assert_source_data(raw, normalized)
    assert normalized.source_data["UnknownField"] == "  unchanged source text  "
    assert normalized.source_data["EmptyField"] == ""
    assert normalized.source_data["SentinelField"] == "-"
    assert raw.model_dump() == before
    normalized.source_data["UnknownField"] = "changed output"
    assert raw.event_data["UnknownField"] == "  unchanged source text  "


@pytest.mark.parametrize(("event_id", "field", "normalized_field"), OPTIONAL_FIELDS)
@pytest.mark.parametrize("value", (None, "", "   ", "-", " - "))
def test_optional_fields_do_not_invent_values(
    event_id: int,
    field: str,
    normalized_field: str,
    value: str | None,
) -> None:
    data = dict(MINIMAL_DATA[event_id])
    if value is not None:
        data[field] = value
    raw = _raw_event(event_id, data)
    normalized = normalize_sysmon_event(raw)

    assert normalized.context.model_dump()[normalized_field] is None
    _assert_source_data(raw, normalized)


@pytest.mark.parametrize(
    ("event_id", "field"),
    (
        (1, "Image"),
        (1, "ProcessId"),
        (3, "SourceIp"),
        (3, "SourcePort"),
        (3, "DestinationIp"),
        (3, "DestinationPort"),
        (11, "TargetFilename"),
        (22, "QueryName"),
    ),
)
@pytest.mark.parametrize("value", (None, "", "   ", "-", " - "))
def test_required_fields_reject_missing_or_sentinel_values(
    event_id: int,
    field: str,
    value: str | None,
) -> None:
    data = dict(MINIMAL_DATA[event_id])
    if value is None:
        del data[field]
    else:
        data[field] = value
    with pytest.raises(InvalidNormalizedEventError, match=field):
        normalize_sysmon_event(_raw_event(event_id, data))


@pytest.mark.parametrize(("event_id", "field"), PROCESS_ID_FIELDS)
@pytest.mark.parametrize(("value", "expected"), (("8000", 8000), ("0", 0), ("08", 8), (" 42 ", 42)))
def test_process_ids_use_decimal_non_negative_integers(
    event_id: int,
    field: str,
    value: str,
    expected: int,
) -> None:
    data = {**MINIMAL_DATA[event_id], field: value}
    normalized = normalize_sysmon_event(_raw_event(event_id, data))
    normalized_field = "parent_process_id" if field == "ParentProcessId" else "process_id"
    assert normalized.context.model_dump()[normalized_field] == expected


@pytest.mark.parametrize(("event_id", "field"), PROCESS_ID_FIELDS)
@pytest.mark.parametrize("value", ("invalid", "-1", "1.5", "0x1f40", "0X1F40"))
def test_invalid_present_process_ids_are_not_treated_as_absent(
    event_id: int,
    field: str,
    value: str,
) -> None:
    with pytest.raises(InvalidNormalizedEventError, match=field):
        normalize_sysmon_event(_raw_event(event_id, {**MINIMAL_DATA[event_id], field: value}))


@pytest.mark.parametrize(
    ("field", "normalized_field"),
    (("SourcePort", "source_port"), ("DestinationPort", "destination_port")),
)
@pytest.mark.parametrize(
    ("value", "expected"), (("0", 0), ("65535", 65535), ("00053", 53), (" 53 ", 53))
)
def test_valid_port_boundaries(
    field: str, normalized_field: str, value: str, expected: int
) -> None:
    normalized = normalize_sysmon_event(_raw_event(3, {**MINIMAL_DATA[3], field: value}))
    assert isinstance(normalized.context, NetworkContext)
    assert normalized.context.model_dump()[normalized_field] == expected


@pytest.mark.parametrize("field", ("SourcePort", "DestinationPort"))
@pytest.mark.parametrize("value", ("-1", "65536", "invalid", "1.5", "0x35"))
def test_invalid_ports_raise_controlled_errors(field: str, value: str) -> None:
    with pytest.raises(InvalidNormalizedEventError) as error:
        normalize_sysmon_event(_raw_event(3, {**MINIMAL_DATA[3], field: value}))
    if value == "65536":
        assert isinstance(error.value.__cause__, ValidationError)


@pytest.mark.parametrize(
    ("field", "normalized_field"), (("SourceIp", "source_ip"), ("DestinationIp", "destination_ip"))
)
@pytest.mark.parametrize("value", ("192.0.2.10", "2001:db8::10", "0.0.0.0", "::"))
def test_valid_ipv4_and_ipv6_addresses(field: str, normalized_field: str, value: str) -> None:
    normalized = normalize_sysmon_event(_raw_event(3, {**MINIMAL_DATA[3], field: value}))
    assert isinstance(normalized.context, NetworkContext)
    assert normalized.context.model_dump(mode="json")[normalized_field] == value


@pytest.mark.parametrize("field", ("SourceIp", "DestinationIp"))
@pytest.mark.parametrize("value", ("not-an-ip", "192.0.2.999", "192.0.2.10/24", "2001:db8::xyz"))
def test_invalid_ips_wrap_pydantic_validation(field: str, value: str) -> None:
    with pytest.raises(InvalidNormalizedEventError) as error:
        normalize_sysmon_event(_raw_event(3, {**MINIMAL_DATA[3], field: value}))
    assert isinstance(error.value.__cause__, ValidationError)


@pytest.mark.parametrize("event_id", FIXTURES)
def test_consumed_text_is_stripped_but_retained_text_is_not(event_id: int) -> None:
    fixture = _fixture_event(event_id)
    data = {name: f"  {value}  " for name, value in fixture.event_data.items()}
    padded_raw = fixture.model_copy(update={"event_data": data})
    normalized = normalize_sysmon_event(padded_raw)
    original = normalize_sysmon_event(fixture)

    assert normalized.context == original.context
    _assert_source_data(padded_raw, normalized)


def test_dns_results_are_not_split_enriched_or_interpreted() -> None:
    normalized = normalize_sysmon_event(
        _raw_event(
            22,
            {
                "QueryName": "api.example.com",
                "QueryStatus": "  synthetic-status  ",
                "QueryResults": "  203.0.113.53;198.51.100.25;synthetic-result  ",
            },
        )
    )
    assert isinstance(normalized.context, DnsContext)
    assert normalized.context.query_status == "synthetic-status"
    assert normalized.context.query_results == "203.0.113.53;198.51.100.25;synthetic-result"


@pytest.mark.parametrize(
    ("provider", "channel", "event_id"),
    (
        ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 9999),
        ("Other-Provider", "Microsoft-Windows-Sysmon/Operational", 1),
        ("Microsoft-Windows-Sysmon", "Other-Channel", 3),
        ("Microsoft-Windows-Security-Auditing", "Security", 4624),
        ("Microsoft-Windows-Sysmon ", "Microsoft-Windows-Sysmon/Operational", 11),
        ("Microsoft-Windows-Sysmon", "microsoft-windows-sysmon/operational", 22),
    ),
)
def test_unsupported_identity_is_rejected_before_field_conversion(
    provider: str,
    channel: str,
    event_id: int,
) -> None:
    raw = _raw_event(1).model_copy(
        update={
            "provider": provider,
            "channel": channel,
            "event_id": event_id,
            "event_data": {"ProcessId": "invalid"},
        }
    )
    with pytest.raises(UnsupportedEventError):
        normalize_sysmon_event(raw)


@pytest.mark.parametrize("event_id", FIXTURES)
@pytest.mark.parametrize("record_id", (None, 0, 2001))
def test_record_id_and_non_utc_timestamp_are_preserved(
    event_id: int,
    record_id: int | None,
) -> None:
    timestamp = datetime(2026, 1, 15, 13, 0, tzinfo=timezone(timedelta(hours=3)))
    raw = _raw_event(event_id).model_copy(update={"record_id": record_id, "timestamp": timestamp})
    _assert_common_metadata(raw, normalize_sysmon_event(raw))


@pytest.mark.parametrize("event_id", FIXTURES)
def test_normalization_is_deterministic(event_id: int) -> None:
    raw = _fixture_event(event_id)
    assert normalize_sysmon_event(raw) == normalize_sysmon_event(raw)


def test_normalization_errors_use_the_existing_common_hierarchy() -> None:
    assert issubclass(EventNormalizationError, ValueError)
    assert issubclass(UnsupportedEventError, EventNormalizationError)
    assert issubclass(InvalidNormalizedEventError, EventNormalizationError)

    with pytest.raises(EventNormalizationError):
        normalize_sysmon_event(_raw_event(1, {}))
    with pytest.raises(EventNormalizationError):
        normalize_sysmon_event(_raw_event(1).model_copy(update={"event_id": 9999}))
