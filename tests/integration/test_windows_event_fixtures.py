"""Quality checks for the synthetic Windows Event XML fixture dataset."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from xml.etree import ElementTree

import pytest

EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NAMESPACES = {"event": EVENT_NAMESPACE}
EVENT_TAG = f"{{{EVENT_NAMESPACE}}}Event"
DATA_TAG = f"{{{EVENT_NAMESPACE}}}Data"
FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "windows"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SECURITY_CHANNEL = "Security"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYNTHETIC_COMPUTER = "WS-01.example.com"
DOCUMENTATION_NETWORKS = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)


@dataclass(frozen=True)
class FixtureSpec:
    """Expected structural and source metadata for one synthetic fixture."""

    relative_path: str
    provider: str
    event_id: int
    channel: str
    required_fields: frozenset[str]
    ip_fields: tuple[str, ...] = ()
    dns_query_field: str | None = None


COMMON_AUTHENTICATION_FIELDS = frozenset(
    {
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
    }
)

FIXTURE_MANIFEST = (
    FixtureSpec(
        "security/security_4624_successful_logon.xml",
        SECURITY_PROVIDER,
        4624,
        SECURITY_CHANNEL,
        COMMON_AUTHENTICATION_FIELDS | {"TargetLogonId"},
        ("IpAddress",),
    ),
    FixtureSpec(
        "security/security_4625_failed_logon.xml",
        SECURITY_PROVIDER,
        4625,
        SECURITY_CHANNEL,
        COMMON_AUTHENTICATION_FIELDS | {"Status", "FailureReason", "SubStatus"},
        ("IpAddress",),
    ),
    FixtureSpec(
        "security/security_4688_process_creation.xml",
        SECURITY_PROVIDER,
        4688,
        SECURITY_CHANNEL,
        frozenset(
            {
                "SubjectUserSid",
                "SubjectUserName",
                "SubjectDomainName",
                "SubjectLogonId",
                "NewProcessId",
                "NewProcessName",
                "TokenElevationType",
                "ProcessId",
                "CommandLine",
            }
        ),
    ),
    FixtureSpec(
        "sysmon/sysmon_1_process_creation.xml",
        SYSMON_PROVIDER,
        1,
        SYSMON_CHANNEL,
        frozenset(
            {
                "RuleName",
                "UtcTime",
                "ProcessGuid",
                "ProcessId",
                "Image",
                "CommandLine",
                "CurrentDirectory",
                "User",
                "LogonGuid",
                "LogonId",
                "IntegrityLevel",
                "Hashes",
                "ParentProcessGuid",
                "ParentProcessId",
                "ParentImage",
                "ParentCommandLine",
            }
        ),
    ),
    FixtureSpec(
        "sysmon/sysmon_3_network_connection.xml",
        SYSMON_PROVIDER,
        3,
        SYSMON_CHANNEL,
        frozenset(
            {
                "RuleName",
                "UtcTime",
                "ProcessGuid",
                "ProcessId",
                "Image",
                "User",
                "Protocol",
                "Initiated",
                "SourceIsIpv6",
                "SourceIp",
                "SourceHostname",
                "SourcePort",
                "DestinationIsIpv6",
                "DestinationIp",
                "DestinationHostname",
                "DestinationPort",
            }
        ),
        ("SourceIp", "DestinationIp"),
    ),
    FixtureSpec(
        "sysmon/sysmon_11_file_create.xml",
        SYSMON_PROVIDER,
        11,
        SYSMON_CHANNEL,
        frozenset(
            {
                "RuleName",
                "UtcTime",
                "ProcessGuid",
                "ProcessId",
                "Image",
                "TargetFilename",
                "CreationUtcTime",
                "User",
            }
        ),
    ),
    FixtureSpec(
        "sysmon/sysmon_22_dns_query.xml",
        SYSMON_PROVIDER,
        22,
        SYSMON_CHANNEL,
        frozenset(
            {
                "RuleName",
                "UtcTime",
                "ProcessGuid",
                "ProcessId",
                "QueryName",
                "QueryStatus",
                "QueryResults",
                "Image",
                "User",
            }
        ),
        ("QueryResults",),
        "QueryName",
    ),
)


def _required_text(parent: ElementTree.Element, path: str) -> str:
    element = parent.find(path, NAMESPACES)
    assert element is not None, f"missing {path}"
    assert element.text is not None, f"empty {path}"
    text = element.text.strip()
    assert text, f"empty {path}"
    return text


def _event_data_fields(event_data: ElementTree.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for child in event_data:
        assert child.tag == DATA_TAG
        name = child.get("Name")
        assert name is not None and name.strip()
        assert name not in fields, f"duplicate EventData field: {name}"
        fields[name] = (child.text or "").strip()
    return fields


def _assert_documentation_ip(value: str) -> None:
    address = IPv4Address(value)
    assert any(address in network for network in DOCUMENTATION_NETWORKS)


@pytest.mark.parametrize("spec", FIXTURE_MANIFEST, ids=lambda spec: spec.relative_path)
def test_windows_event_fixture_quality(spec: FixtureSpec) -> None:
    fixture_path = FIXTURE_ROOT / spec.relative_path
    assert fixture_path.is_file()

    root = ElementTree.parse(fixture_path).getroot()
    assert root.tag == EVENT_TAG
    assert sum(element.tag == EVENT_TAG for element in root.iter()) == 1

    system = root.find("event:System", NAMESPACES)
    event_data = root.find("event:EventData", NAMESPACES)
    assert system is not None
    assert event_data is not None

    provider = system.find("event:Provider", NAMESPACES)
    assert provider is not None
    assert provider.get("Name") == spec.provider
    assert int(_required_text(system, "event:EventID")) == spec.event_id
    assert spec.event_id > 0
    assert _required_text(system, "event:Version")
    assert _required_text(system, "event:Level")
    assert _required_text(system, "event:Task")
    assert _required_text(system, "event:Opcode")
    assert _required_text(system, "event:Keywords")
    assert _required_text(system, "event:Channel") == spec.channel
    assert _required_text(system, "event:Computer") == SYNTHETIC_COMPUTER

    execution = system.find("event:Execution", NAMESPACES)
    assert execution is not None
    assert execution.get("ProcessID")
    assert execution.get("ThreadID")

    time_created = system.find("event:TimeCreated", NAMESPACES)
    assert time_created is not None
    system_time = time_created.get("SystemTime")
    assert system_time is not None
    parsed_time = datetime.fromisoformat(system_time.replace("Z", "+00:00"))
    assert parsed_time.tzinfo is not None
    assert parsed_time.utcoffset() is not None

    record_id = int(_required_text(system, "event:EventRecordID"))
    assert record_id > 0

    fields = _event_data_fields(event_data)
    assert spec.required_fields <= fields.keys()
    for field_name in spec.ip_fields:
        _assert_documentation_ip(fields[field_name])
    if spec.dns_query_field is not None:
        query_name = fields[spec.dns_query_field].lower()
        assert query_name == "example.com" or query_name.endswith(".example.com")


def test_fixture_manifest_is_complete() -> None:
    assert len(FIXTURE_MANIFEST) == 7
    expected_paths = {FIXTURE_ROOT / spec.relative_path for spec in FIXTURE_MANIFEST}
    assert set(FIXTURE_ROOT.rglob("*.xml")) == expected_paths
