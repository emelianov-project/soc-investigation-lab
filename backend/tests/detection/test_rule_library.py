"""Synthetic end-to-end examples for the real, committed demonstration rules."""

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.detection import evaluate_condition, evaluate_event, load_detection_rules
from app.models import ConditionOutcome, ConditionTrace, DetectionRule, EventCategory, EventSource
from app.models.normalized_event import NormalizedEvent

RULE_ROOT = Path(__file__).resolve().parents[3] / "rules" / "windows"

# This is an expected library inventory, not a second set of rule definitions.
INVENTORY = {
    "account/failed-remote-authentication.yaml": (
        "failed-remote-authentication",
        "Failed network or remote-interactive authentication",
        EventCategory.AUTHENTICATION,
    ),
    "execution/certutil-suspicious-arguments.yaml": (
        "certutil-suspicious-arguments",
        "Certutil transfer or decode argument",
        EventCategory.PROCESS,
    ),
    "execution/powershell-encoded-command.yaml": (
        "powershell-encoded-command",
        "PowerShell encoded-command argument",
        EventCategory.PROCESS,
    ),
    "network/dns-suspicious-query-marker.yaml": (
        "dns-suspicious-query-marker",
        "DNS demonstration query marker",
        EventCategory.DNS,
    ),
    "network/powershell-network-connection.yaml": (
        "powershell-network-connection",
        "PowerShell-associated network connection",
        EventCategory.NETWORK,
    ),
    "persistence/startup-folder-file-activity.yaml": (
        "startup-folder-file-activity",
        "Startup-folder file activity",
        EventCategory.FILE,
    ),
}


@pytest.fixture
def library() -> tuple[DetectionRule, ...]:
    return load_detection_rules(RULE_ROOT)


def event(
    category: EventCategory,
    context: dict[str, object],
    source: EventSource = EventSource.SYSMON,
) -> NormalizedEvent:
    """Construct safe normalized telemetry with supported source/event identities."""
    security = source is EventSource.WINDOWS_SECURITY
    event_id = {
        EventCategory.AUTHENTICATION: 4624 if context.get("outcome") == "success" else 4625,
        EventCategory.PROCESS: 4688 if security else 1,
        EventCategory.NETWORK: 3,
        EventCategory.FILE: 11,
        EventCategory.DNS: 22,
    }[category]
    return NormalizedEvent.model_validate(
        {
            "source": source,
            "provider": "Microsoft-Windows-Security-Auditing"
            if security
            else "Microsoft-Windows-Sysmon",
            "channel": "Security" if security else "Microsoft-Windows-Sysmon/Operational",
            "event_id": event_id,
            "timestamp": datetime(2026, 9, 26, 12, tzinfo=UTC),
            "computer": "workstation.example.com",
            "record_id": 42,
            "category": category,
            "context": context,
        }
    )


def network_event(process_image: str | None) -> NormalizedEvent:
    return event(
        EventCategory.NETWORK,
        {
            "source_ip": "192.0.2.10",
            "source_port": 50000,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "process_image": process_image,
        },
    )


def leaves(trace: ConditionTrace) -> Iterator[ConditionTrace]:
    if trace.kind == "leaf":
        yield trace
    for child in trace.children:
        yield from leaves(child)


def assert_match(
    normalized: NormalizedEvent,
    library: tuple[DetectionRule, ...],
    rule_id: str,
    evidence: Sequence[tuple[str, str, object]],
) -> None:
    matches = evaluate_event(normalized, library)
    # Category targeting and each rule's discriminators prevent unrelated matches.
    assert [match.rule_id for match in matches] == [rule_id]
    matched = matches[0]
    selected = next(rule for rule in library if rule.id == rule_id)
    assert (matched.rule_version, matched.rule_title) == (1, selected.title)
    assert matched.event is normalized
    assert matched.event.record_id == 42
    assert matched.event.computer == "workstation.example.com"
    assert matched.root_outcome is ConditionOutcome.TRUE
    assert matched.trace.location == "$"
    assert matched.trace.outcome is ConditionOutcome.TRUE
    leaf_traces = list(leaves(matched.trace))
    assert leaf_traces
    assert all(leaf.field is not None and leaf.field.startswith("context.") for leaf in leaf_traces)
    assert all("actual" in leaf.model_fields_set for leaf in leaf_traces)
    for field, operator, expected in evidence:
        assert any(
            leaf.field == field
            and leaf.op is not None
            and leaf.op.value == operator
            and leaf.expected == expected
            and leaf.outcome is ConditionOutcome.TRUE
            for leaf in leaf_traces
        ), (rule_id, field, operator, expected)


def test_library_inventory_schema_order_and_repeated_loads(
    library: tuple[DetectionRule, ...],
) -> None:
    paths = sorted(
        path.relative_to(RULE_ROOT).as_posix()
        for path in RULE_ROOT.rglob("*")
        if path.is_file() and path.suffix in {".yaml", ".yml"}
    )
    assert paths == list(INVENTORY)
    assert len(library) == len({rule.id for rule in library}) == 6
    assert [(rule.id, rule.title, rule.categories[0]) for rule in library] == list(
        INVENTORY.values()
    )
    assert {category for rule in library for category in rule.categories} == set(EventCategory)
    for rule in library:
        assert isinstance(rule, DetectionRule)
        assert rule.version == 1
        assert len(rule.categories) == 1
        assert rule.sources is None
        # Source-data conditions cannot load without sources; none are needed here.
        assert rule.model_fields_set == {
            "id",
            "version",
            "title",
            "description",
            "categories",
            "condition",
        }
    assert [rule.model_dump() for rule in load_detection_rules(RULE_ROOT)] == [
        rule.model_dump() for rule in library
    ]


def test_library_root_does_not_depend_on_working_directory(
    library: tuple[DetectionRule, ...], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_detection_rules(RULE_ROOT) == library


@pytest.mark.parametrize("source", list(EventSource))
@pytest.mark.parametrize("image", [r"C:\Windows\System32\powershell.exe", r"C:\Example\pwsh.exe"])
@pytest.mark.parametrize("argument", ["-EncodedCommand", "-encodedcommand", "-enc"])
def test_powershell_encoded_command_matches_with_explanation(
    library: tuple[DetectionRule, ...], source: EventSource, image: str, argument: str
) -> None:
    normalized = event(
        EventCategory.PROCESS,
        {"image": image, "command_line": f"{image} {argument} BENIGN_PLACEHOLDER"},
        source,
    )
    assert_match(
        normalized,
        library,
        "powershell-encoded-command",
        [
            ("context.image", "ends_with", "\\" + image.rsplit("\\", 1)[1]),
            (
                "context.command_line",
                "contains_any",
                [" -EncodedCommand ", " -encodedcommand ", " -enc "],
            ),
        ],
    )


@pytest.mark.parametrize("source", list(EventSource))
@pytest.mark.parametrize("argument", ["-urlcache", "-decode"])
def test_certutil_arguments_match_with_explanation(
    library: tuple[DetectionRule, ...], source: EventSource, argument: str
) -> None:
    # No executable payload or real remote destination is used, or executed.
    operands = (
        "https://example.com/sample.txt" if argument == "-urlcache" else r"C:\Example\sample.txt"
    )
    normalized = event(
        EventCategory.PROCESS,
        {
            "image": r"C:\Windows\System32\certutil.exe",
            "command_line": f"certutil.exe {argument} {operands}",
        },
        source,
    )
    assert_match(
        normalized,
        library,
        "certutil-suspicious-arguments",
        [
            ("context.image", "ends_with", r"\certutil.exe"),
            ("context.command_line", "contains_any", [" -urlcache ", " -decode "]),
        ],
    )


@pytest.mark.parametrize("logon_type", [3, 10])
def test_failed_remote_authentication_matches_with_explanation(
    library: tuple[DetectionRule, ...], logon_type: int
) -> None:
    normalized = event(
        EventCategory.AUTHENTICATION,
        {"outcome": "failure", "logon_type": logon_type, "user": "test-user"},
        EventSource.WINDOWS_SECURITY,
    )
    assert_match(
        normalized,
        library,
        "failed-remote-authentication",
        [
            ("context.outcome", "equals", "failure"),
            ("context.logon_type", "in", [3, 10]),
        ],
    )


@pytest.mark.parametrize("executable", ["powershell.exe", "pwsh.exe"])
def test_powershell_network_matches_with_explanation(
    library: tuple[DetectionRule, ...], executable: str
) -> None:
    assert_match(
        network_event("C:\\Example\\" + executable),
        library,
        "powershell-network-connection",
        [
            ("context.process_image", "ends_with", "\\" + executable),
        ],
    )


def test_dns_marker_matches_with_explanation(library: tuple[DetectionRule, ...]) -> None:
    assert_match(
        event(EventCategory.DNS, {"query_name": "tunnel-test.example.com"}),
        library,
        "dns-suspicious-query-marker",
        [("context.query_name", "contains", "tunnel-test")],
    )


@pytest.mark.parametrize(
    "prefix",
    [r"C:\Users\test-user\AppData\Roaming\Microsoft\Windows", r"C:\ProgramData\Microsoft\Windows"],
)
def test_startup_file_matches_with_explanation(
    library: tuple[DetectionRule, ...], prefix: str
) -> None:
    fragment = "\\Start Menu\\Programs\\Startup\\"
    assert_match(
        event(EventCategory.FILE, {"target_path": prefix + fragment + "example.txt"}),
        library,
        "startup-folder-file-activity",
        [("context.target_path", "contains", fragment)],
    )


@pytest.mark.parametrize("source", list(EventSource))
@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        (r"C:\Example\powershell.exe", "powershell.exe -NoProfile"),
        (r"C:\Example\example.exe", "example.exe -EncodedCommand BENIGN_PLACEHOLDER"),
        (r"C:\Example\PowerShell.exe", "PowerShell.exe -EncodedCommand BENIGN_PLACEHOLDER"),
        (r"C:\Example\powershell.exe", "powershell.exe -ENCODEDCOMMAND BENIGN_PLACEHOLDER"),
        (r"C:\Example\powershell.exe", "powershell.exe -encoder BENIGN_PLACEHOLDER"),
        (r"C:\Example\certutil.exe", "certutil.exe -hashfile C:\\Example\\sample.txt SHA256"),
        (r"C:\Example\example.exe", "example.exe -decode C:\\Example\\sample.txt"),
        (r"C:\Example\certutil.exe", "certutil.exe -DECODE C:\\Example\\sample.txt"),
        (r"C:\Example\certutil.exe", "certutil.exe -decodehex C:\\Example\\sample.txt"),
    ],
)
def test_process_negatives_and_case_sensitive_markers(
    library: tuple[DetectionRule, ...], source: EventSource, image: str, command_line: str
) -> None:
    assert (
        evaluate_event(
            event(EventCategory.PROCESS, {"image": image, "command_line": command_line}, source),
            library,
        )
        == ()
    )


@pytest.mark.parametrize(
    ("outcome", "logon_type"), [("success", 3), ("success", 10), ("failure", 2)]
)
def test_authentication_negatives(
    library: tuple[DetectionRule, ...], outcome: str, logon_type: int
) -> None:
    normalized = event(
        EventCategory.AUTHENTICATION,
        {"outcome": outcome, "logon_type": logon_type},
        EventSource.WINDOWS_SECURITY,
    )
    assert evaluate_event(normalized, library) == ()


@pytest.mark.parametrize("image", [r"C:\Example\browser.exe", r"C:\Example\PowerShell.exe"])
def test_network_negatives(library: tuple[DetectionRule, ...], image: str) -> None:
    assert evaluate_event(network_event(image), library) == ()


@pytest.mark.parametrize("query", ["www.example.com", "TUNNEL-TEST.example.com"])
def test_dns_negatives(library: tuple[DetectionRule, ...], query: str) -> None:
    assert evaluate_event(event(EventCategory.DNS, {"query_name": query}), library) == ()


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\test-user\Documents\example.txt",
        r"C:\Example\Start Menu\Programs\startup\example.txt",
    ],
)
def test_file_negatives(library: tuple[DetectionRule, ...], path: str) -> None:
    assert evaluate_event(event(EventCategory.FILE, {"target_path": path}), library) == ()


@pytest.mark.parametrize(
    ("rule_id", "normalized", "field"),
    [
        (
            "powershell-encoded-command",
            event(
                EventCategory.PROCESS, {"image": r"C:\Example\powershell.exe", "command_line": None}
            ),
            "context.command_line",
        ),
        (
            "certutil-suspicious-arguments",
            event(
                EventCategory.PROCESS, {"image": r"C:\Example\certutil.exe", "command_line": None}
            ),
            "context.command_line",
        ),
        (
            "failed-remote-authentication",
            event(
                EventCategory.AUTHENTICATION,
                {"outcome": "failure", "logon_type": None},
                EventSource.WINDOWS_SECURITY,
            ),
            "context.logon_type",
        ),
        ("powershell-network-connection", network_event(None), "context.process_image"),
    ],
)
def test_optional_absence_is_unknown_and_never_matches(
    library: tuple[DetectionRule, ...], rule_id: str, normalized: NormalizedEvent, field: str
) -> None:
    assert evaluate_event(normalized, library) == ()
    selected = next(rule for rule in library if rule.id == rule_id)
    trace = evaluate_condition(normalized, selected.condition)
    assert trace.outcome is ConditionOutcome.UNKNOWN
    absent = [leaf for leaf in leaves(trace) if leaf.field == field]
    assert absent
    for leaf in absent:
        assert leaf.absence == "absent"
        assert leaf.outcome is ConditionOutcome.UNKNOWN
        assert "actual" not in leaf.model_fields_set
