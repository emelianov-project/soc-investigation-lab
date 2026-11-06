"""Offline integration from synthetic Windows Event XML through the analyst queue."""

import sys
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from textwrap import indent
from traceback import format_exception
from typing import cast
from xml.etree import ElementTree

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))

from app.alerts import (  # noqa: E402
    AlertCreationError,
    AlertPolicyError,
    AlertQueueError,
    AlertTransitionError,
    acknowledge_alert,
    close_alert,
    create_alert,
    list_alerts,
    set_priority,
    set_severity,
)
from app.detection import (  # noqa: E402
    DetectionRuleFileError,
    DuplicateDetectionRuleIdError,
    evaluate_event,
    load_detection_rules,
)
from app.models import (  # noqa: E402
    Alert,
    AlertPriority,
    AlertSeverity,
    AlertState,
    ConditionOutcome,
    DetectionMatch,
    EventCategory,
    EventSource,
    ProcessContext,
)
from app.parsers import (  # noqa: E402
    MalformedEventXmlError,
    UnsupportedEventError,
    normalize_windows_event_xml,
)

FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures" / "windows"
RULE_ROOT = REPOSITORY_ROOT / "rules" / "windows"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SECURITY_PROCESS = "security/security_4688_process_creation.xml"
FAILED_LOGON = "security/security_4625_failed_logon.xml"
DNS_QUERY = "sysmon/sysmon_22_dns_query.xml"
POWERSHELL_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
DNS_CHANGES = {"QueryName": "tunnel-test.example.com"}
START = datetime(2026, 10, 1, 12, tzinfo=UTC)
ACK_AT = START + timedelta(minutes=1)
SEVERITY_AT = START + timedelta(minutes=2)
PRIORITY_AT = START + timedelta(minutes=3)
CLOSE_AT = START + timedelta(minutes=4)
OFFSET = timezone(timedelta(hours=5, minutes=30))
HOST = "alert-evidence-fixture.example.com"
EVENT_TEXT = "synthetic-event-text-fixture"
SOURCE_VALUE = "synthetic-source-data-fixture"
TRACE_EXPECTED = "synthetic-trace-expected-fixture"
TRACE_ACTUAL = f"observed-{TRACE_EXPECTED}"
EVIDENCE_SENTINELS = (HOST, EVENT_TEXT, SOURCE_VALUE, TRACE_EXPECTED, TRACE_ACTUAL)


@dataclass(frozen=True)
class Signal:
    rule_id: str
    fixture: str
    source: EventSource
    category: EventCategory
    changes: Mapping[str, str] | None = None


SIGNALS = (
    Signal(
        "failed-remote-authentication",
        FAILED_LOGON,
        EventSource.WINDOWS_SECURITY,
        EventCategory.AUTHENTICATION,
    ),
    Signal(
        "certutil-suspicious-arguments",
        SECURITY_PROCESS,
        EventSource.WINDOWS_SECURITY,
        EventCategory.PROCESS,
        {
            "NewProcessName": r"C:\Windows\System32\certutil.exe",
            "CommandLine": "certutil.exe -urlcache https://example.com/sample.txt",
        },
    ),
    Signal(
        "powershell-encoded-command",
        "sysmon/sysmon_1_process_creation.xml",
        EventSource.SYSMON,
        EventCategory.PROCESS,
        {
            "Image": POWERSHELL_IMAGE,
            "CommandLine": "powershell.exe -EncodedCommand BENIGN_PLACEHOLDER",
        },
    ),
    Signal(
        "powershell-network-connection",
        "sysmon/sysmon_3_network_connection.xml",
        EventSource.SYSMON,
        EventCategory.NETWORK,
        {"Image": POWERSHELL_IMAGE},
    ),
    Signal(
        "startup-folder-file-activity",
        "sysmon/sysmon_11_file_create.xml",
        EventSource.SYSMON,
        EventCategory.FILE,
        {
            "TargetFilename": (
                r"C:\Users\test-user\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\example.txt"
            ),
        },
    ),
    Signal(
        "dns-suspicious-query-marker",
        DNS_QUERY,
        EventSource.SYSMON,
        EventCategory.DNS,
        DNS_CHANGES,
    ),
)


def _xml(
    fixture: str,
    changes: Mapping[str, str] | None = None,
    *,
    system: Mapping[str, str] | None = None,
) -> str:
    xml = (FIXTURE_ROOT / fixture).read_text(encoding="utf-8")
    if not changes and not system:
        return xml
    root = ElementTree.fromstring(xml)
    for name, value in (changes or {}).items():
        elements = root.findall(f"{NS}EventData/{NS}Data[@Name='{name}']")
        assert len(elements) == 1, f"expected one EventData field {name}"
        elements[0].text = value
    for name, value in (system or {}).items():
        element = root.find(f"{NS}System/{NS}{name}")
        assert element is not None, f"missing System field {name}"
        element.text = value
    return ElementTree.tostring(root, encoding="unicode")


def _evaluate_xml(xml: str, rule_root: Path = RULE_ROOT) -> tuple[DetectionMatch, ...]:
    event = normalize_windows_event_xml(xml)
    return evaluate_event(event, load_detection_rules(rule_root))


def _handle(alert: Alert) -> tuple[Alert, Alert, Alert, Alert]:
    acknowledged = acknowledge_alert(alert, ACK_AT)
    assessed = set_severity(acknowledged, AlertSeverity.HIGH, SEVERITY_AT)
    prioritized = set_priority(assessed, AlertPriority.URGENT, PRIORITY_AT)
    closed = close_alert(prioritized, CLOSE_AT)
    return acknowledged, assessed, prioritized, closed


@pytest.mark.parametrize("signal", SIGNALS, ids=[signal.rule_id for signal in SIGNALS])
def test_real_xml_rule_and_full_alert_lifecycle(signal: Signal) -> None:
    xml = _xml(signal.fixture, signal.changes)
    event = normalize_windows_event_xml(xml)
    original_event = event.model_dump(mode="python")
    rules = load_detection_rules(RULE_ROOT)
    assert {rule.id for rule in rules} == {case.rule_id for case in SIGNALS}
    (match,) = evaluate_event(event, rules)
    rule = next(rule for rule in rules if rule.id == signal.rule_id)
    assert (match.rule_id, match.rule_version, match.rule_title) == (
        rule.id,
        rule.version,
        rule.title,
    )
    assert match.event == event
    assert (event.source, event.category) == (signal.source, signal.category)
    assert match.root_outcome is match.trace.outcome is ConditionOutcome.TRUE
    assert match.trace.location == "$"
    evidence = match.model_dump(mode="python", exclude_unset=True)

    alert_id = f"example-{signal.rule_id}"
    created = create_alert(match, alert_id, START.astimezone(OFFSET))
    acknowledged, assessed, prioritized, closed = _handle(created)
    assert (created.alert_id, created.state, created.severity, created.priority) == (
        alert_id,
        AlertState.NEW,
        AlertSeverity.UNASSIGNED,
        AlertPriority.NORMAL,
    )
    assert created.created_at == created.state_changed_at == created.updated_at == START
    assert created.created_at.tzinfo is UTC

    initial = created.model_dump(mode="python")
    acknowledged_data = initial | {
        "state": AlertState.ACKNOWLEDGED,
        "state_changed_at": ACK_AT,
        "updated_at": ACK_AT,
    }
    assessed_data = acknowledged_data | {"severity": AlertSeverity.HIGH, "updated_at": SEVERITY_AT}
    prioritized_data = assessed_data | {"priority": AlertPriority.URGENT, "updated_at": PRIORITY_AT}
    assert acknowledged.model_dump() == acknowledged_data
    assert assessed.model_dump() == assessed_data
    assert prioritized.model_dump() == prioritized_data
    assert closed.model_dump() == prioritized_data | {
        "state": AlertState.CLOSED,
        "state_changed_at": CLOSE_AT,
        "updated_at": CLOSE_AT,
    }
    assert "verdict" not in closed.model_dump()
    for alert in (created, acknowledged, assessed, prioritized, closed):
        source_match = alert.source_match
        assert source_match == match
        assert source_match.model_dump(mode="python", exclude_unset=True) == evidence
        assert type(source_match.event.context) is type(event.context)
    assert event.model_dump(mode="python") == original_event
    assert match.model_dump(mode="python", exclude_unset=True) == evidence

    assert list_alerts([closed]) == ()
    (fresh_match,) = _evaluate_xml(xml)
    repeated = _handle(create_alert(fresh_match, alert_id, START))[-1]
    assert list_alerts([repeated], states={AlertState.CLOSED}) == (closed,)


def test_real_match_and_external_evidence_copies_are_detached() -> None:
    signal = next(case for case in SIGNALS if case.category is EventCategory.NETWORK)
    event = normalize_windows_event_xml(_xml(signal.fixture, signal.changes))
    (match,) = evaluate_event(event, load_detection_rules(RULE_ROOT))
    expected = match.model_dump(mode="python", exclude_unset=True)
    created = create_alert(match, "network-example", START)

    match.rule_title = "changed synthetic title"
    match.trace.outcome = ConditionOutcome.FALSE
    event.source_data["RuleName"] = "changed synthetic source data"
    exposed = created.source_match
    exposed.event.source_data.clear()
    exposed.trace.outcome = ConditionOutcome.UNKNOWN
    assert created.source_match.model_dump(mode="python", exclude_unset=True) == expected

    before = created.model_dump(mode="python")
    acknowledged, assessed, prioritized, closed = _handle(created)
    assert created.model_dump(mode="python") == before
    for alert in (acknowledged, assessed, prioritized, closed):
        assert alert.source_match.model_dump(mode="python", exclude_unset=True) == expected


def test_queue_filters_and_total_order_across_real_alerts() -> None:
    (security,) = _evaluate_xml(_xml(FAILED_LOGON))
    (sysmon,) = _evaluate_xml(_xml(DNS_QUERY, DNS_CHANGES))

    def high_priority(
        alert_id: str, severity: AlertSeverity, created_at: datetime = START
    ) -> Alert:
        return create_alert(
            security,
            alert_id,
            created_at,
            severity=severity,
            priority=AlertPriority.HIGH,
        )

    urgent = create_alert(sysmon, "urgent", ACK_AT, priority=AlertPriority.URGENT)
    critical = high_priority("critical", AlertSeverity.CRITICAL, ACK_AT)
    oldest = high_priority("z-oldest", AlertSeverity.HIGH, START - timedelta(seconds=1))
    tie_first = high_priority("tie-2", AlertSeverity.HIGH, START.astimezone(OFFSET))
    tie_second = acknowledge_alert(high_priority("tie-a", AlertSeverity.HIGH), ACK_AT)
    medium = high_priority("medium", AlertSeverity.MEDIUM)
    low = high_priority("low", AlertSeverity.LOW)
    informational = high_priority("informational", AlertSeverity.INFORMATIONAL)
    unassigned = high_priority("a-unassigned", AlertSeverity.UNASSIGNED, oldest.created_at)
    normal = create_alert(sysmon, "normal", START, severity=AlertSeverity.CRITICAL)
    low_priority = create_alert(
        sysmon,
        "low-priority",
        START,
        severity=AlertSeverity.CRITICAL,
        priority=AlertPriority.LOW,
    )
    closed = _handle(create_alert(sysmon, "closed", START))[-1]
    active = (
        urgent,
        critical,
        oldest,
        tie_first,
        tie_second,
        medium,
        low,
        informational,
        unassigned,
        normal,
        low_priority,
    )
    batch = [*reversed(active), closed]
    assert list_alerts(batch) == active
    assert list_alerts(batch[3:] + batch[:3]) == active
    assert list_alerts(batch, states={AlertState.CLOSED}) == (closed,)
    assert list_alerts(batch, states=set(AlertState)) == (closed, *active)
    assert list_alerts(batch, severities={AlertSeverity.UNASSIGNED}) == (urgent, unassigned)
    assert list_alerts(batch, priorities={AlertPriority.LOW}) == (low_priority,)
    assert list_alerts(
        batch,
        states={AlertState.NEW, AlertState.ACKNOWLEDGED},
        severities={AlertSeverity.HIGH, AlertSeverity.UNASSIGNED},
        priorities={AlertPriority.URGENT, AlertPriority.HIGH},
    ) == (urgent, oldest, tie_first, tie_second, unassigned)
    assert tie_first.created_at == tie_second.created_at == START
    assert tie_first.created_at.tzinfo is UTC
    assert batch == [*reversed(active), closed]


def _rule_yaml(
    rule_id: str,
    *,
    version: int = 1,
    condition: str = "field: event_id\nop: equals\nvalue: 4688\n",
) -> str:
    return (
        f"id: {rule_id}\nversion: {version}\n"
        "title: Synthetic alert integration rule\n"
        "description: Select synthetic process evidence for an Alert test.\n"
        "categories: [process]\nsources: [windows_security]\ncondition:\n" + indent(condition, "  ")
    )


def test_multiple_matches_get_distinct_explicit_ids_and_repeatable_queue(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(_rule_yaml("z-example"), encoding="utf-8")
    (tmp_path / "b.yml").write_text(_rule_yaml("a-example"), encoding="utf-8")
    xml = _xml(SECURITY_PROCESS)
    ids = ("alert-z", "alert-a")

    def run() -> tuple[Alert, ...]:
        matches = _evaluate_xml(xml, tmp_path)
        assert tuple(match.rule_id for match in matches) == ("a-example", "z-example")
        alerts = [
            create_alert(match, alert_id, START)
            for match, alert_id in zip(matches, ids, strict=True)
        ]
        assert tuple(alert.source_match for alert in alerts) == matches
        return list_alerts(alerts)

    queued = run()
    assert tuple(alert.alert_id for alert in queued) == ("alert-a", "alert-z")
    assert tuple(alert.source_match.rule_id for alert in queued) == ("z-example", "a-example")
    assert run() == list_alerts(queued[::-1]) == queued


def test_nonmatching_xml_leaves_queue_empty() -> None:
    matches = _evaluate_xml(_xml("security/security_4624_successful_logon.xml"))
    alerts = tuple(create_alert(match, "example-alert", START) for match in matches)
    assert matches == ()
    assert list_alerts(alerts) == ()


def _assert_no_evidence(error: BaseException) -> None:
    checked: set[int] = set()
    pending = [error]
    while pending:
        failure = pending.pop()
        if id(failure) in checked:
            continue
        checked.add(id(failure))
        diagnostics = (str(failure), repr(failure), repr(vars(failure)), *format_exception(failure))
        assert all(marker not in text for marker in EVIDENCE_SENTINELS for text in diagnostics)
        pending.extend(
            cause for cause in (failure.__cause__, failure.__context__) if cause is not None
        )


type AlertError = AlertCreationError | AlertTransitionError | AlertPolicyError | AlertQueueError


def _assert_safe_alert_error(error: AlertError, reason: str, field: str) -> None:
    assert (error.reason, error.field) == (reason, field)
    assert error.__cause__ is error.__context__ is None
    assert "ValidationError" not in repr(error)
    assert "ValidationError" not in "".join(format_exception(error))
    _assert_no_evidence(error)


@pytest.mark.parametrize("malformed", [True, False], ids=["malformed", "unsupported"])
def test_bad_xml_stops_before_matching(malformed: bool) -> None:
    xml = _xml(SECURITY_PROCESS, {"SubjectLogonId": SOURCE_VALUE}, system={"Computer": HOST})
    if malformed:
        xml = xml.rsplit("<", 1)[0]
        error_type: type[ValueError] = MalformedEventXmlError
    else:
        xml = _xml(SECURITY_PROCESS, system={"Computer": HOST, "EventID": "9999"})
        error_type = UnsupportedEventError
    with pytest.raises(error_type) as caught:
        _evaluate_xml(xml)
    _assert_no_evidence(caught.value)


@pytest.mark.parametrize(
    ("bad_rule", "category"),
    [
        ("condition: [unfinished", "invalid_yaml"),
        ("condition: &anchor {field: event_id, op: equals, value: 4688}", "unsafe_yaml"),
    ],
    ids=["malformed-yaml", "unsafe-anchor"],
)
def test_bad_yaml_stops_matching_even_after_a_valid_rule(
    tmp_path: Path, bad_rule: str, category: str
) -> None:
    (tmp_path / "a-valid.yaml").write_text(_rule_yaml("a-valid"), encoding="utf-8")
    (tmp_path / "z-invalid.yaml").write_text(bad_rule, encoding="utf-8")
    xml = _xml(SECURITY_PROCESS, system={"Computer": HOST})
    with pytest.raises(DetectionRuleFileError) as caught:
        _evaluate_xml(xml, tmp_path)
    assert (caught.value.path, caught.value.category) == ("z-invalid.yaml", category)
    _assert_no_evidence(caught.value)


def test_duplicate_rule_ids_stop_matching_across_versions(tmp_path: Path) -> None:
    for filename, version in (("a.yaml", 1), ("b.yml", 2)):
        (tmp_path / filename).write_text(
            _rule_yaml("example-rule", version=version), encoding="utf-8"
        )
    with pytest.raises(DuplicateDetectionRuleIdError) as caught:
        _evaluate_xml(_xml(SECURITY_PROCESS, system={"Computer": HOST}), tmp_path)
    error = caught.value
    assert (error.rule_id, error.first_path, error.duplicate_path) == (
        "example-rule",
        "a.yaml",
        "b.yml",
    )
    _assert_no_evidence(error)


@pytest.fixture
def sentinel_match(tmp_path: Path) -> DetectionMatch:
    condition = f"field: source_data.TokenElevationType\nop: contains\nvalue: {TRACE_EXPECTED}\n"
    (tmp_path / "sentinel.yaml").write_text(
        _rule_yaml("synthetic-sentinel-rule", condition=condition), encoding="utf-8"
    )
    xml = _xml(
        SECURITY_PROCESS,
        {
            "CommandLine": EVENT_TEXT,
            "SubjectLogonId": SOURCE_VALUE,
            "TokenElevationType": TRACE_ACTUAL,
        },
        system={"Computer": HOST},
    )
    (match,) = _evaluate_xml(xml, tmp_path)
    assert match.event.computer == HOST
    assert isinstance(match.event.context, ProcessContext)
    assert match.event.context.command_line == EVENT_TEXT
    assert match.event.source_data["SubjectLogonId"] == SOURCE_VALUE
    assert (match.trace.expected, match.trace.actual) == (TRACE_EXPECTED, TRACE_ACTUAL)
    return match


@pytest.mark.parametrize(
    ("alert_id", "at", "reason", "field"),
    [
        ("invalid alert id", START, "invalid_alert_id", "alert_id"),
        ("example-alert", START.replace(tzinfo=None), "invalid_created_at", "created_at"),
        ("example-alert", "not-a-timestamp", "invalid_created_at", "created_at"),
    ],
    ids=["invalid-id", "naive-time", "malformed-time"],
)
def test_creation_rejects_bad_inputs_without_mutating_real_match(
    sentinel_match: DetectionMatch, alert_id: str, at: object, reason: str, field: str
) -> None:
    before = sentinel_match.model_dump()
    with pytest.raises(AlertCreationError) as caught:
        create_alert(sentinel_match, alert_id, cast(datetime, at))
    _assert_safe_alert_error(caught.value, reason, field)
    assert sentinel_match.model_dump() == before


def test_mutated_real_match_fails_without_serializer_echo(sentinel_match: DetectionMatch) -> None:
    before = sentinel_match.model_dump()
    invalid = sentinel_match.model_copy(update={"root_outcome": TRACE_ACTUAL})
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertCreationError) as caught:
            create_alert(invalid, "example-alert", START)
    assert not emitted
    _assert_safe_alert_error(caught.value, "invalid_match", "match")
    assert sentinel_match.model_dump() == before
    assert create_alert(sentinel_match, "example-alert", START).source_match == sentinel_match


def test_lifecycle_and_policy_failures_are_atomic(sentinel_match: DetectionMatch) -> None:
    created = create_alert(sentinel_match, "example-alert", START)
    acknowledged, _, prioritized, closed = _handle(created)
    alerts = (created, acknowledged, prioritized, closed)
    before = tuple(alert.model_dump() for alert in alerts)
    requests: tuple[
        tuple[Callable[[], Alert], type[AlertTransitionError | AlertPolicyError], str, str], ...
    ] = (
        (
            partial(close_alert, created, CLOSE_AT),
            AlertTransitionError,
            "forbidden_transition",
            "state",
        ),
        (
            partial(acknowledge_alert, closed, CLOSE_AT),
            AlertTransitionError,
            "forbidden_transition",
            "state",
        ),
        (partial(close_alert, acknowledged, START), AlertTransitionError, "out_of_order_at", "at"),
        (
            partial(set_severity, closed, AlertSeverity.LOW, CLOSE_AT),
            AlertPolicyError,
            "closed_alert",
            "state",
        ),
        (
            partial(set_priority, prioritized, AlertPriority.NORMAL, ACK_AT),
            AlertPolicyError,
            "out_of_order_changed_at",
            "changed_at",
        ),
    )
    for request, error_type, reason, field in requests:
        with pytest.raises(error_type) as caught:
            request()
        _assert_safe_alert_error(
            cast(AlertTransitionError | AlertPolicyError, caught.value), reason, field
        )
    assert tuple(alert.model_dump() for alert in alerts) == before


@pytest.mark.parametrize("duplicate", [True, False], ids=["duplicate-id", "invalid-evidence"])
def test_queue_failure_is_atomic_even_when_closed_entry_would_be_hidden(
    sentinel_match: DetectionMatch, duplicate: bool
) -> None:
    active = create_alert(sentinel_match, "visible-alert", START)
    closed_id = active.alert_id if duplicate else "closed-alert"
    closed = _handle(create_alert(sentinel_match, closed_id, START))[-1]
    bad_entry = (
        closed
        if duplicate
        else closed.model_copy(
            update={
                "source_match": sentinel_match.model_copy(update={"root_outcome": TRACE_ACTUAL})
            }
        )
    )
    before = active.model_dump(), closed.model_dump()
    batch = [active, bad_entry]
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertQueueError) as caught:
            list_alerts(batch, severities={AlertSeverity.UNASSIGNED})
    reason, field = ("duplicate_alert_id", "alert_id") if duplicate else ("invalid_alert", "alerts")
    _assert_safe_alert_error(caught.value, reason, field)
    assert not emitted
    assert (active.model_dump(), closed.model_dump()) == before
    assert batch[0] is active and batch[1] is bad_entry
    assert list_alerts([active]) == (active,)
