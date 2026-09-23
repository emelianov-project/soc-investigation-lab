"""End-to-end coverage for the public Windows event-processing pipeline."""

import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))

from app.models import (  # noqa: E402
    AuthenticationContext,
    DnsContext,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    NormalizedEvent,
    ProcessContext,
)
from app.parsers import (  # noqa: E402
    InvalidNormalizedEventError,
    InvalidRawEventError,
    MalformedEventXmlError,
    UnsupportedEventError,
    normalize_windows_event_xml,
)

WINDOWS_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "windows"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SECURITY_CHANNEL = "Security"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYNTHETIC_COMPUTER = "WS-01.example.com"

ContextType = type[
    AuthenticationContext | ProcessContext | NetworkContext | FileContext | DnsContext
]


@dataclass(frozen=True)
class SuccessCase:
    """Expected end-to-end result for one committed synthetic fixture."""

    relative_path: str
    provider: str
    event_id: int
    channel: str
    record_id: int
    source: EventSource
    category: EventCategory
    context_type: ContextType
    representative_context: Mapping[str, object]


SUCCESS_CASES = (
    SuccessCase(
        "security/security_4624_successful_logon.xml",
        SECURITY_PROVIDER,
        4624,
        SECURITY_CHANNEL,
        1001,
        EventSource.WINDOWS_SECURITY,
        EventCategory.AUTHENTICATION,
        AuthenticationContext,
        {
            "outcome": "success",
            "user": "lab.user",
            "logon_type": 3,
            "source_ip": "192.0.2.10",
        },
    ),
    SuccessCase(
        "security/security_4625_failed_logon.xml",
        SECURITY_PROVIDER,
        4625,
        SECURITY_CHANNEL,
        1002,
        EventSource.WINDOWS_SECURITY,
        EventCategory.AUTHENTICATION,
        AuthenticationContext,
        {
            "outcome": "failure",
            "user": "test.user",
            "logon_type": 3,
            "source_ip": "198.51.100.25",
        },
    ),
    SuccessCase(
        "security/security_4688_process_creation.xml",
        SECURITY_PROVIDER,
        4688,
        SECURITY_CHANNEL,
        1003,
        EventSource.WINDOWS_SECURITY,
        EventCategory.PROCESS,
        ProcessContext,
        {
            "image": r"C:\Windows\System32\cmd.exe",
            "process_id": 8000,
            "command_line": "cmd.exe /c echo synthetic-fixture",
        },
    ),
    SuccessCase(
        "sysmon/sysmon_1_process_creation.xml",
        SYSMON_PROVIDER,
        1,
        SYSMON_CHANNEL,
        2001,
        EventSource.SYSMON,
        EventCategory.PROCESS,
        ProcessContext,
        {"image": r"C:\Windows\System32\cmd.exe", "process_id": 8000},
    ),
    SuccessCase(
        "sysmon/sysmon_3_network_connection.xml",
        SYSMON_PROVIDER,
        3,
        SYSMON_CHANNEL,
        2002,
        EventSource.SYSMON,
        EventCategory.NETWORK,
        NetworkContext,
        {
            "source_ip": "192.0.2.10",
            "source_port": 53000,
            "destination_ip": "203.0.113.53",
            "destination_port": 53,
        },
    ),
    SuccessCase(
        "sysmon/sysmon_11_file_create.xml",
        SYSMON_PROVIDER,
        11,
        SYSMON_CHANNEL,
        2003,
        EventSource.SYSMON,
        EventCategory.FILE,
        FileContext,
        {"target_path": r"C:\Users\lab.user\Documents\synthetic.txt"},
    ),
    SuccessCase(
        "sysmon/sysmon_22_dns_query.xml",
        SYSMON_PROVIDER,
        22,
        SYSMON_CHANNEL,
        2004,
        EventSource.SYSMON,
        EventCategory.DNS,
        DnsContext,
        {"query_name": "api.example.com"},
    ),
)


def _tag(local_name: str) -> str:
    return f"{{{WINDOWS_EVENT_NAMESPACE}}}{local_name}"


def _fixture_xml(relative_path: str) -> str:
    return (FIXTURE_ROOT / relative_path).read_text(encoding="utf-8")


def _mutated_fixture(
    relative_path: str,
    mutation: Callable[[ElementTree.Element], None],
) -> str:
    root = ElementTree.fromstring(_fixture_xml(relative_path))
    mutation(root)
    return ElementTree.tostring(root, encoding="unicode")


def _required_child(parent: ElementTree.Element, local_name: str) -> ElementTree.Element:
    child = parent.find(_tag(local_name))
    assert child is not None
    return child


def _system(root: ElementTree.Element) -> ElementTree.Element:
    return _required_child(root, "System")


def _set_system_text(root: ElementTree.Element, local_name: str, value: str) -> None:
    _required_child(_system(root), local_name).text = value


def _set_provider(root: ElementTree.Element, value: str) -> None:
    _required_child(_system(root), "Provider").set("Name", value)


def _set_timestamp(root: ElementTree.Element, value: str) -> None:
    _required_child(_system(root), "TimeCreated").set("SystemTime", value)


def _remove_system_child(root: ElementTree.Element, local_name: str) -> None:
    system = _system(root)
    system.remove(_required_child(system, local_name))


def _event_data(root: ElementTree.Element) -> ElementTree.Element:
    return _required_child(root, "EventData")


def _set_event_data_value(root: ElementTree.Element, name: str, value: str) -> None:
    for data in _event_data(root).findall(_tag("Data")):
        if data.get("Name") == name:
            data.text = value
            return
    raise AssertionError(f"fixture is missing EventData field {name!r}")


def _remove_event_data(root: ElementTree.Element) -> None:
    root.remove(_event_data(root))


@pytest.mark.parametrize("case", SUCCESS_CASES, ids=lambda case: case.relative_path)
def test_all_supported_fixtures_normalize_end_to_end(case: SuccessCase) -> None:
    normalized = normalize_windows_event_xml(_fixture_xml(case.relative_path))

    assert isinstance(normalized, NormalizedEvent)
    assert normalized.provider == case.provider
    assert normalized.event_id == case.event_id
    assert normalized.channel == case.channel
    assert normalized.computer == SYNTHETIC_COMPUTER
    assert normalized.record_id == case.record_id
    assert normalized.timestamp.tzinfo is not None
    assert normalized.timestamp.utcoffset() is not None
    assert normalized.source == case.source
    assert normalized.category == case.category
    assert isinstance(normalized.context, case.context_type)

    context = normalized.context.model_dump(mode="json")
    for field_name, expected_value in case.representative_context.items():
        assert context[field_name] == expected_value


def test_malformed_xml_raises_the_controlled_ingestion_error() -> None:
    with pytest.raises(MalformedEventXmlError):
        normalize_windows_event_xml("<Event>")


def test_missing_required_system_metadata_raises_invalid_raw_event() -> None:
    xml = _mutated_fixture(
        "security/security_4624_successful_logon.xml",
        lambda root: _remove_system_child(root, "Computer"),
    )

    with pytest.raises(InvalidRawEventError):
        normalize_windows_event_xml(xml)


@pytest.mark.parametrize("event_id", ("not-an-integer", "0"))
def test_invalid_raw_event_id_is_distinct_from_unsupported_event(event_id: str) -> None:
    xml = _mutated_fixture(
        "security/security_4624_successful_logon.xml",
        lambda root: _set_system_text(root, "EventID", event_id),
    )

    with pytest.raises(InvalidRawEventError):
        normalize_windows_event_xml(xml)


@pytest.mark.parametrize(
    "timestamp",
    ("not-a-timestamp", "2026-01-15T10:00:00"),
    ids=("malformed", "timezone-naive"),
)
def test_invalid_timestamp_raises_invalid_raw_event(timestamp: str) -> None:
    xml = _mutated_fixture(
        "security/security_4624_successful_logon.xml",
        lambda root: _set_timestamp(root, timestamp),
    )

    with pytest.raises(InvalidRawEventError):
        normalize_windows_event_xml(xml)


def test_unsupported_provider_is_rejected_by_registry_dispatch() -> None:
    xml = _mutated_fixture(
        "security/security_4624_successful_logon.xml",
        lambda root: _set_provider(root, "Example-Unsupported-Provider"),
    )

    with pytest.raises(UnsupportedEventError):
        normalize_windows_event_xml(xml)


def test_positive_but_unsupported_event_id_is_rejected_by_registry_dispatch() -> None:
    xml = _mutated_fixture(
        "sysmon/sysmon_1_process_creation.xml",
        lambda root: _set_system_text(root, "EventID", "9999"),
    )

    with pytest.raises(UnsupportedEventError):
        normalize_windows_event_xml(xml)


def test_absent_optional_event_data_does_not_invent_authentication_values() -> None:
    xml = _mutated_fixture(
        "security/security_4624_successful_logon.xml",
        _remove_event_data,
    )

    normalized = normalize_windows_event_xml(xml)

    assert isinstance(normalized, NormalizedEvent)
    assert isinstance(normalized.context, AuthenticationContext)
    assert normalized.context.outcome.value == "success"
    assert normalized.context.user is None
    assert normalized.context.domain is None
    assert normalized.context.logon_type is None
    assert normalized.context.source_ip is None
    assert normalized.context.source_port is None
    assert normalized.context.workstation is None
    assert normalized.source_data == {}


def test_invalid_process_identifier_raises_normalization_error() -> None:
    xml = _mutated_fixture(
        "sysmon/sysmon_1_process_creation.xml",
        lambda root: _set_event_data_value(root, "ProcessId", "not-an-integer"),
    )

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_event_xml(xml)


def test_invalid_typed_ip_raises_normalization_error() -> None:
    xml = _mutated_fixture(
        "sysmon/sysmon_3_network_connection.xml",
        lambda root: _set_event_data_value(root, "SourceIp", "not-an-ip"),
    )

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_event_xml(xml)


def test_out_of_range_typed_port_raises_normalization_error() -> None:
    xml = _mutated_fixture(
        "sysmon/sysmon_3_network_connection.xml",
        lambda root: _set_event_data_value(root, "DestinationPort", "65536"),
    )

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_event_xml(xml)


def test_source_normalizer_validation_error_propagates_through_pipeline() -> None:
    xml = _mutated_fixture(
        "sysmon/sysmon_11_file_create.xml",
        lambda root: _set_event_data_value(root, "TargetFilename", "-"),
    )

    with pytest.raises(InvalidNormalizedEventError):
        normalize_windows_event_xml(xml)
