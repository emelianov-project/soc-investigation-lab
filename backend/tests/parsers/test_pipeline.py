"""Tests for the explicit event-normalizer registry and XML pipeline."""

from pathlib import Path

import pytest
from app.models import EventCategory, EventSource, NormalizedEvent
from app.parsers import (
    EVENT_NORMALIZER_REGISTRY,
    InvalidNormalizedEventError,
    InvalidRawEventError,
    MalformedEventXmlError,
    UnsupportedEventError,
    get_event_normalizer,
    normalize_sysmon_event,
    normalize_windows_event_xml,
    normalize_windows_security_event,
    parse_windows_event_xml,
)

FIXTURE_ROOT = Path(__file__).parents[3] / "tests" / "fixtures" / "windows"
WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
WINDOWS_SECURITY_IDENTITIES = frozenset(
    {
        (WINDOWS_SECURITY_PROVIDER, 4624),
        (WINDOWS_SECURITY_PROVIDER, 4625),
        (WINDOWS_SECURITY_PROVIDER, 4688),
    }
)
SYSMON_IDENTITIES = frozenset(
    {
        (SYSMON_PROVIDER, 1),
        (SYSMON_PROVIDER, 3),
        (SYSMON_PROVIDER, 11),
        (SYSMON_PROVIDER, 22),
    }
)
FIXTURE_CASES = (
    (
        "security/security_4624_successful_logon.xml",
        EventSource.WINDOWS_SECURITY,
        EventCategory.AUTHENTICATION,
    ),
    (
        "security/security_4625_failed_logon.xml",
        EventSource.WINDOWS_SECURITY,
        EventCategory.AUTHENTICATION,
    ),
    (
        "security/security_4688_process_creation.xml",
        EventSource.WINDOWS_SECURITY,
        EventCategory.PROCESS,
    ),
    (
        "sysmon/sysmon_1_process_creation.xml",
        EventSource.SYSMON,
        EventCategory.PROCESS,
    ),
    (
        "sysmon/sysmon_3_network_connection.xml",
        EventSource.SYSMON,
        EventCategory.NETWORK,
    ),
    (
        "sysmon/sysmon_11_file_create.xml",
        EventSource.SYSMON,
        EventCategory.FILE,
    ),
    (
        "sysmon/sysmon_22_dns_query.xml",
        EventSource.SYSMON,
        EventCategory.DNS,
    ),
)


def _fixture_xml(relative_path: str) -> str:
    return (FIXTURE_ROOT / relative_path).read_text(encoding="utf-8")


def test_registry_contains_exactly_the_supported_identities() -> None:
    assert set(EVENT_NORMALIZER_REGISTRY) == WINDOWS_SECURITY_IDENTITIES | SYSMON_IDENTITIES


def test_registry_dispatches_windows_security_identities() -> None:
    for identity in WINDOWS_SECURITY_IDENTITIES:
        raw = parse_windows_event_xml(
            _fixture_xml(
                f"security/security_{identity[1]}_"
                + {
                    4624: "successful_logon.xml",
                    4625: "failed_logon.xml",
                    4688: "process_creation.xml",
                }[identity[1]]
            )
        )
        assert get_event_normalizer(raw) is normalize_windows_security_event


def test_registry_dispatches_sysmon_identities() -> None:
    fixture_names = {
        1: "sysmon_1_process_creation.xml",
        3: "sysmon_3_network_connection.xml",
        11: "sysmon_11_file_create.xml",
        22: "sysmon_22_dns_query.xml",
    }
    for identity in SYSMON_IDENTITIES:
        raw = parse_windows_event_xml(_fixture_xml(f"sysmon/{fixture_names[identity[1]]}"))
        assert get_event_normalizer(raw) is normalize_sysmon_event


@pytest.mark.parametrize(("relative_path", "source", "category"), FIXTURE_CASES)
def test_all_supported_fixtures_pass_through_pipeline(
    relative_path: str,
    source: EventSource,
    category: EventCategory,
) -> None:
    normalized = normalize_windows_event_xml(_fixture_xml(relative_path))

    assert isinstance(normalized, NormalizedEvent)
    assert normalized.source == source
    assert normalized.category == category


def test_unknown_provider_is_reported_by_registry() -> None:
    xml = _fixture_xml("security/security_4624_successful_logon.xml").replace(
        WINDOWS_SECURITY_PROVIDER,
        "Example-Provider",
        1,
    )

    with pytest.raises(
        UnsupportedEventError, match="unsupported event provider: 'Example-Provider'"
    ):
        normalize_windows_event_xml(xml)


def test_known_provider_with_unsupported_event_id_is_reported_by_registry() -> None:
    xml = _fixture_xml("sysmon/sysmon_1_process_creation.xml").replace(
        "<EventID>1</EventID>",
        "<EventID>9999</EventID>",
        1,
    )

    with pytest.raises(
        UnsupportedEventError,
        match="unsupported event ID 9999 for provider 'Microsoft-Windows-Sysmon'",
    ):
        normalize_windows_event_xml(xml)


def test_wrong_channel_reaches_the_source_normalizer() -> None:
    xml = _fixture_xml("security/security_4624_successful_logon.xml").replace(
        "<Channel>Security</Channel>",
        "<Channel>Invalid</Channel>",
        1,
    )

    with pytest.raises(UnsupportedEventError, match="unsupported Windows Security identity"):
        normalize_windows_event_xml(xml)


def test_controlled_normalization_failure_propagates() -> None:
    xml = _fixture_xml("security/security_4688_process_creation.xml").replace(
        r'<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>',
        '<Data Name="NewProcessName">-</Data>',
        1,
    )

    with pytest.raises(InvalidNormalizedEventError, match="NewProcessName is required"):
        normalize_windows_event_xml(xml)


def test_ingestion_errors_propagate_without_conversion() -> None:
    with pytest.raises(MalformedEventXmlError):
        normalize_windows_event_xml("<Event>")
    with pytest.raises(InvalidRawEventError):
        normalize_windows_event_xml("<NotEvent />")
