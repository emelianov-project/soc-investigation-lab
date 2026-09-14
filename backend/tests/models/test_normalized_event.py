"""Unit tests for normalized-event domain contracts."""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

import pytest
from app.models import (
    AuthenticationContext,
    AuthenticationOutcome,
    DnsContext,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    NormalizedEvent,
    ProcessContext,
)
from pydantic import ValidationError

TIMESTAMP = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)


def make_event(
    category: EventCategory,
    context: AuthenticationContext | ProcessContext | NetworkContext | FileContext | DnsContext,
) -> NormalizedEvent:
    """Build a valid synthetic normalized event for focused tests."""
    return NormalizedEvent(
        source=EventSource.SYSMON,
        provider="Microsoft-Windows-Sysmon",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        timestamp=TIMESTAMP,
        computer="workstation.example.com",
        record_id=42,
        category=category,
        context=context,
        source_data={},
    )


def make_authentication_event() -> NormalizedEvent:
    """Build a representative authentication event."""
    return NormalizedEvent(
        source=EventSource.WINDOWS_SECURITY,
        provider="Microsoft-Windows-Security-Auditing",
        event_id=4624,
        channel="Security",
        timestamp=TIMESTAMP,
        computer="workstation.example.com",
        record_id=17,
        category=EventCategory.AUTHENTICATION,
        context=AuthenticationContext(
            outcome=AuthenticationOutcome.SUCCESS,
            user="analyst",
            domain="LAB",
            logon_type=3,
            source_ip=IPv4Address("192.0.2.10"),
            source_port=49152,
            workstation="WORKSTATION",
        ),
        source_data={"TargetLogonId": "0x123"},
    )


def test_valid_authentication_event() -> None:
    event = make_authentication_event()

    assert event.category is EventCategory.AUTHENTICATION
    assert isinstance(event.context, AuthenticationContext)
    assert event.context.outcome is AuthenticationOutcome.SUCCESS


def test_valid_process_event() -> None:
    event = make_event(
        EventCategory.PROCESS,
        ProcessContext(
            image=r"C:\Windows\System32\whoami.exe",
            process_id=4120,
            command_line="whoami.exe /all",
            parent_process_id=700,
            parent_image=r"C:\Windows\System32\cmd.exe",
            user=r"LAB\analyst",
        ),
    )

    assert event.category is EventCategory.PROCESS
    assert isinstance(event.context, ProcessContext)


def test_valid_network_event() -> None:
    event = make_event(
        EventCategory.NETWORK,
        NetworkContext(
            source_ip=IPv4Address("192.0.2.25"),
            source_port=51324,
            destination_ip=IPv4Address("198.51.100.40"),
            destination_port=443,
            protocol="tcp",
            process_id=4120,
            process_image=r"C:\Program Files\Example\client.exe",
        ),
    )

    assert event.category is EventCategory.NETWORK
    assert isinstance(event.context, NetworkContext)


def test_valid_file_event() -> None:
    event = make_event(
        EventCategory.FILE,
        FileContext(
            target_path=r"C:\Lab\output.txt",
            process_id=4120,
            process_image=r"C:\Windows\System32\notepad.exe",
        ),
    )

    assert event.category is EventCategory.FILE
    assert isinstance(event.context, FileContext)


def test_valid_dns_event() -> None:
    event = make_event(
        EventCategory.DNS,
        DnsContext(
            query_name="example.com",
            query_status="0",
            query_results="203.0.113.10",
            process_id=4120,
            process_image=r"C:\Program Files\Example\client.exe",
        ),
    )

    assert event.category is EventCategory.DNS
    assert isinstance(event.context, DnsContext)


def test_event_source_rejects_unsupported_value() -> None:
    with pytest.raises(ValueError):
        EventSource("linux_audit")


def test_event_category_rejects_unsupported_value() -> None:
    with pytest.raises(ValueError):
        EventCategory("alert")


def test_authentication_outcome_rejects_unsupported_value() -> None:
    with pytest.raises(ValueError):
        AuthenticationOutcome("unknown")


@pytest.mark.parametrize(
    "field",
    ("source", "provider", "event_id", "channel", "timestamp", "computer", "category", "context"),
)
def test_missing_required_common_metadata_fails(field: str) -> None:
    data = make_authentication_event().model_dump()
    del data[field]

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_event_id_zero_fails() -> None:
    data = make_authentication_event().model_dump()
    data["event_id"] = 0

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_negative_event_id_fails() -> None:
    data = make_authentication_event().model_dump()
    data["event_id"] = -1

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_boolean_event_id_fails() -> None:
    data = make_authentication_event().model_dump()
    data["event_id"] = True

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_negative_record_id_fails() -> None:
    data = make_authentication_event().model_dump()
    data["record_id"] = -1

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_record_id_may_be_absent() -> None:
    data = make_authentication_event().model_dump()
    del data["record_id"]

    event = NormalizedEvent.model_validate(data)

    assert event.record_id is None


def test_naive_timestamp_fails() -> None:
    data = make_authentication_event().model_dump()
    data["timestamp"] = datetime(2026, 9, 13, 12, 0)

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_timezone_aware_timestamp_succeeds() -> None:
    event = make_authentication_event()

    assert event.timestamp.tzinfo is UTC


def test_invalid_ip_address_fails() -> None:
    with pytest.raises(ValidationError):
        NetworkContext.model_validate(
            {
                "source_ip": "not-an-ip-address",
                "source_port": 443,
                "destination_ip": "198.51.100.40",
                "destination_port": 443,
            }
        )


def test_ipv4_addresses_succeed() -> None:
    context = NetworkContext(
        source_ip=IPv4Address("192.0.2.25"),
        source_port=51324,
        destination_ip=IPv4Address("198.51.100.40"),
        destination_port=443,
    )

    assert context.source_ip == IPv4Address("192.0.2.25")
    assert context.destination_ip == IPv4Address("198.51.100.40")


def test_ipv6_addresses_succeed() -> None:
    context = NetworkContext(
        source_ip=IPv6Address("2001:db8::10"),
        source_port=51324,
        destination_ip=IPv6Address("2001:db8::20"),
        destination_port=443,
    )

    assert context.source_ip == IPv6Address("2001:db8::10")
    assert context.destination_ip == IPv6Address("2001:db8::20")


def test_negative_process_id_fails() -> None:
    with pytest.raises(ValidationError):
        ProcessContext(image="cmd.exe", process_id=-1)


def test_boolean_process_id_fails() -> None:
    with pytest.raises(ValidationError):
        ProcessContext(image="cmd.exe", process_id=True)


def test_negative_parent_process_id_fails() -> None:
    with pytest.raises(ValidationError):
        ProcessContext(image="cmd.exe", parent_process_id=-1)


def test_negative_logon_type_fails() -> None:
    with pytest.raises(ValidationError):
        AuthenticationContext(outcome=AuthenticationOutcome.FAILURE, logon_type=-1)


def test_negative_port_fails() -> None:
    with pytest.raises(ValidationError):
        AuthenticationContext(
            outcome=AuthenticationOutcome.FAILURE,
            source_port=-1,
        )


def test_port_above_maximum_fails() -> None:
    with pytest.raises(ValidationError):
        AuthenticationContext(
            outcome=AuthenticationOutcome.FAILURE,
            source_port=65_536,
        )


def test_boolean_port_fails() -> None:
    with pytest.raises(ValidationError):
        AuthenticationContext(
            outcome=AuthenticationOutcome.FAILURE,
            source_port=True,
        )


@pytest.mark.parametrize(
    ("category", "context"),
    (
        (EventCategory.AUTHENTICATION, ProcessContext(image="cmd.exe")),
        (EventCategory.PROCESS, DnsContext(query_name="example.com")),
        (
            EventCategory.NETWORK,
            FileContext(target_path=r"C:\Lab\output.txt"),
        ),
        (
            EventCategory.FILE,
            NetworkContext(
                source_ip=IPv4Address("192.0.2.25"),
                source_port=443,
                destination_ip=IPv4Address("198.51.100.40"),
                destination_port=443,
            ),
        ),
        (
            EventCategory.DNS,
            AuthenticationContext(outcome=AuthenticationOutcome.SUCCESS),
        ),
    ),
)
def test_category_context_mismatch_fails(
    category: EventCategory,
    context: AuthenticationContext | ProcessContext | NetworkContext | FileContext | DnsContext,
) -> None:
    with pytest.raises(ValidationError, match="requires"):
        make_event(category, context)


def test_extra_normalized_event_field_fails() -> None:
    data = make_authentication_event().model_dump()
    data["unexpected"] = "not allowed"

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_extra_context_field_fails() -> None:
    with pytest.raises(ValidationError):
        ProcessContext.model_validate({"image": "cmd.exe", "unexpected": "not allowed"})


def test_optional_source_fields_remain_absent() -> None:
    context = AuthenticationContext(outcome=AuthenticationOutcome.FAILURE)

    assert context.user is None
    assert context.domain is None
    assert context.logon_type is None
    assert context.source_ip is None
    assert context.source_port is None
    assert context.workstation is None


def test_source_data_preserves_unknown_named_string_field() -> None:
    event = make_authentication_event()

    assert event.source_data == {"TargetLogonId": "0x123"}


def test_source_data_preserves_empty_string_value() -> None:
    data = make_authentication_event().model_dump()
    data["source_data"] = {"SourceField": ""}

    event = NormalizedEvent.model_validate(data)

    assert event.source_data["SourceField"] == ""


def test_non_string_source_data_value_fails() -> None:
    data = make_authentication_event().model_dump()
    data["source_data"] = {"TargetLogonId": 123}

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


def test_nested_source_data_value_fails() -> None:
    data = make_authentication_event().model_dump()
    data["source_data"] = {"Nested": {"value": "not allowed"}}

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


@pytest.mark.parametrize("field", ("provider", "channel", "computer"))
def test_empty_common_string_fails(field: str) -> None:
    data = make_authentication_event().model_dump()
    data[field] = ""

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(data)


@pytest.mark.parametrize(
    ("context_type", "field"),
    (
        (ProcessContext, "image"),
        (FileContext, "target_path"),
        (DnsContext, "query_name"),
    ),
)
def test_empty_required_context_string_fails(
    context_type: type[ProcessContext] | type[FileContext] | type[DnsContext],
    field: str,
) -> None:
    with pytest.raises(ValidationError):
        context_type.model_validate({field: ""})


def test_model_dump_retains_typed_python_values() -> None:
    event = make_authentication_event()

    dumped = event.model_dump()

    assert dumped["source"] is EventSource.WINDOWS_SECURITY
    assert dumped["category"] is EventCategory.AUTHENTICATION
    assert dumped["timestamp"] == TIMESTAMP
    assert dumped["context"]["source_ip"] == IPv4Address("192.0.2.10")


def test_json_mode_dump_has_json_safe_values() -> None:
    event = make_authentication_event()

    dumped = event.model_dump(mode="json")

    assert dumped["source"] == "windows_security"
    assert dumped["category"] == "authentication"
    assert dumped["timestamp"] == "2026-09-13T12:00:00Z"
    assert dumped["context"]["source_ip"] == "192.0.2.10"
    assert dumped["source_data"] == {"TargetLogonId": "0x123"}


def test_model_dump_json_is_deterministic() -> None:
    event = make_authentication_event()

    assert event.model_dump_json() == event.model_dump_json()


def test_json_round_trip_preserves_event() -> None:
    event = make_authentication_event()

    restored = NormalizedEvent.model_validate_json(event.model_dump_json())

    assert restored == event


def test_json_mode_mapping_round_trip_preserves_event() -> None:
    event = make_authentication_event()

    restored = NormalizedEvent.model_validate(event.model_dump(mode="json"))

    assert restored == event
