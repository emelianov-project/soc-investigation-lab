"""Offline XML-to-match integration using real parsers, rules, and detection APIs."""

import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from textwrap import indent
from xml.etree import ElementTree

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))

from app.detection import (  # noqa: E402
    DetectionRuleFileError,
    DuplicateDetectionRuleIdError,
    IncompatibleDetectionConditionError,
    InvalidDetectionFieldError,
    evaluate_condition,
    evaluate_event,
    load_detection_rules,
)
from app.models import (  # noqa: E402
    ConditionOutcome,
    ConditionTrace,
    DetectionMatch,
    DetectionOperator,
    DetectionRule,
)
from app.parsers import normalize_windows_event_xml  # noqa: E402

FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures" / "windows"
RULE_ROOT = REPOSITORY_ROOT / "rules" / "windows"
NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
SECURITY_PROCESS = "security/security_4688_process_creation.xml"
SYSMON_PROCESS = "sysmon/sysmon_1_process_creation.xml"
FAILED_LOGON = "security/security_4625_failed_logon.xml"
SUCCESSFUL_LOGON = "security/security_4624_successful_logon.xml"
NETWORK = "sysmon/sysmon_3_network_connection.xml"
FILE_CREATE = "sysmon/sysmon_11_file_create.xml"
DNS_QUERY = "sysmon/sysmon_22_dns_query.xml"
POWERSHELL_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
POWERSHELL_COMMAND = "powershell.exe -EncodedCommand BENIGN_PLACEHOLDER"
CERTUTIL_COMMAND = "certutil.exe -urlcache https://example.com/sample.txt"
STARTUP_PATH = (
    r"C:\Users\test-user\AppData\Roaming\Microsoft\Windows"
    r"\Start Menu\Programs\Startup\example.txt"
)
EXPECTED_RULE_IDS = {
    "failed-remote-authentication",
    "certutil-suspicious-arguments",
    "powershell-encoded-command",
    "dns-suspicious-query-marker",
    "powershell-network-connection",
    "startup-folder-file-activity",
}


@dataclass(frozen=True)
class MatchCase:
    """XML-only stimulus plus selected expected evidence, not a rule definition."""

    fixture: str
    rule_id: str
    changes: Mapping[str, str]
    field: str
    operator: DetectionOperator
    expected: object
    actual: object


POSITIVE_CASES = (
    # The unchanged 4625 fixture intentionally matches single-event failure triage.
    MatchCase(
        FAILED_LOGON,
        "failed-remote-authentication",
        {},
        "context.logon_type",
        DetectionOperator.IN,
        [3, 10],
        3,
    ),
    *(
        MatchCase(
            fixture,
            "powershell-encoded-command",
            {image_field: POWERSHELL_IMAGE, "CommandLine": POWERSHELL_COMMAND},
            "context.command_line",
            DetectionOperator.CONTAINS_ANY,
            [" -EncodedCommand ", " -encodedcommand ", " -enc "],
            POWERSHELL_COMMAND,
        )
        for fixture, image_field in (
            (SECURITY_PROCESS, "NewProcessName"),
            (SYSMON_PROCESS, "Image"),
        )
    ),
    *(
        MatchCase(
            fixture,
            "certutil-suspicious-arguments",
            {image_field: r"C:\Windows\System32\certutil.exe", "CommandLine": CERTUTIL_COMMAND},
            "context.command_line",
            DetectionOperator.CONTAINS_ANY,
            [" -urlcache ", " -decode "],
            CERTUTIL_COMMAND,
        )
        for fixture, image_field in (
            (SECURITY_PROCESS, "NewProcessName"),
            (SYSMON_PROCESS, "Image"),
        )
    ),
    MatchCase(
        NETWORK,
        "powershell-network-connection",
        {"Image": POWERSHELL_IMAGE},
        "context.process_image",
        DetectionOperator.ENDS_WITH,
        r"\powershell.exe",
        POWERSHELL_IMAGE,
    ),
    MatchCase(
        DNS_QUERY,
        "dns-suspicious-query-marker",
        {"QueryName": "tunnel-test.example.com"},
        "context.query_name",
        DetectionOperator.CONTAINS,
        "tunnel-test",
        "tunnel-test.example.com",
    ),
    MatchCase(
        FILE_CREATE,
        "startup-folder-file-activity",
        {"TargetFilename": STARTUP_PATH},
        "context.target_path",
        DetectionOperator.CONTAINS,
        "\\Start Menu\\Programs\\Startup\\",
        STARTUP_PATH,
    ),
)


def _xml(fixture: str, changes: Mapping[str, str | None] | None = None) -> str:
    """Change only requested EventData values in memory; None removes an element."""
    xml = (FIXTURE_ROOT / fixture).read_text(encoding="utf-8")
    if not changes:
        return xml
    root = ElementTree.fromstring(xml)
    data = root.find(f"{{{NAMESPACE}}}EventData")
    assert data is not None
    for name, value in changes.items():
        elements = [child for child in data if child.get("Name") == name]
        assert len(elements) == 1, f"expected one fixture field {name!r}"
        if value is None:
            data.remove(elements[0])
        else:
            elements[0].text = value
    return ElementTree.tostring(root, encoding="unicode")


def _leaves(trace: ConditionTrace) -> Iterator[ConditionTrace]:
    if trace.kind == "leaf":
        yield trace
    for child in trace.children:
        yield from _leaves(child)


def _rule_yaml(
    rule_id: str = "synthetic-integration-rule",
    *,
    condition: str = "field: event_id\nop: equals\nvalue: 4688\n",
    category: str = "process",
    sources: str = "",
    version: int = 1,
) -> str:
    """Tiny temporary test rule, never a reconstruction of committed library rules."""
    return (
        f"id: {rule_id}\nversion: {version}\n"
        "title: Synthetic integration rule\n"
        "description: Match synthetic XML-normalized telemetry for integration testing.\n"
        f"categories: [{category}]\n"
        f"{sources}"
        "condition:\n" + indent(condition, "  ")
    )


def _write_rule(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def real_rules() -> tuple[DetectionRule, ...]:
    return load_detection_rules(RULE_ROOT)


def test_real_library_and_xml_scenarios_cover_exactly_the_six_initial_rules(
    real_rules: tuple[DetectionRule, ...],
) -> None:
    assert len(real_rules) == 6
    assert {rule.id for rule in real_rules} == EXPECTED_RULE_IDS
    assert {case.rule_id for case in POSITIVE_CASES} == EXPECTED_RULE_IDS


@pytest.mark.parametrize("case", POSITIVE_CASES, ids=lambda case: f"{case.rule_id}-{case.fixture}")
def test_xml_to_real_rule_match_preserves_event_and_explanation(
    case: MatchCase, real_rules: tuple[DetectionRule, ...]
) -> None:
    normalized = normalize_windows_event_xml(_xml(case.fixture, case.changes))
    matches = evaluate_event(normalized, real_rules)
    assert [match.rule_id for match in matches] == [case.rule_id]
    matched = matches[0]
    selected = next(rule for rule in real_rules if rule.id == case.rule_id)
    assert isinstance(matched, DetectionMatch)
    assert (matched.rule_version, matched.rule_title) == (1, selected.title)
    assert normalized.category in selected.categories
    assert matched.event is normalized
    assert matched.event.model_dump() == normalized.model_dump()
    assert matched.event.computer == "WS-01.example.com"
    assert matched.event.record_id is not None
    assert matched.root_outcome is ConditionOutcome.TRUE
    assert (matched.trace.location, matched.trace.outcome) == ("$", ConditionOutcome.TRUE)
    assert any(
        leaf.field == case.field
        and leaf.op is case.operator
        and leaf.expected == case.expected
        and leaf.actual == case.actual
        and leaf.outcome is ConditionOutcome.TRUE
        for leaf in _leaves(matched.trace)
    )


@pytest.mark.parametrize(
    "fixture",
    [
        SUCCESSFUL_LOGON,
        SECURITY_PROCESS,
        SYSMON_PROCESS,
        NETWORK,
        FILE_CREATE,
        DNS_QUERY,
    ],
)
def test_unmodified_ordinary_xml_returns_zero_matches(
    fixture: str, real_rules: tuple[DetectionRule, ...]
) -> None:
    normalized = normalize_windows_event_xml(_xml(fixture))
    assert evaluate_event(normalized, real_rules) == ()


@pytest.mark.parametrize(
    ("fixture", "changes", "rule_id", "field"),
    [
        (
            SECURITY_PROCESS,
            {"NewProcessName": POWERSHELL_IMAGE, "CommandLine": None},
            "powershell-encoded-command",
            "command_line",
        ),
        (
            SYSMON_PROCESS,
            {"Image": POWERSHELL_IMAGE, "CommandLine": None},
            "powershell-encoded-command",
            "command_line",
        ),
        (FAILED_LOGON, {"LogonType": None}, "failed-remote-authentication", "logon_type"),
        (NETWORK, {"Image": None}, "powershell-network-connection", "process_image"),
    ],
)
def test_removed_optional_xml_fields_normalize_to_absence_without_matches(
    fixture: str,
    changes: Mapping[str, str | None],
    rule_id: str,
    field: str,
    real_rules: tuple[DetectionRule, ...],
) -> None:
    normalized = normalize_windows_event_xml(_xml(fixture, changes))
    assert normalized.context.model_dump()[field] is None
    assert evaluate_event(normalized, real_rules) == ()
    selected = next(rule for rule in real_rules if rule.id == rule_id)
    trace = evaluate_condition(normalized, selected.condition)
    assert trace.outcome is ConditionOutcome.UNKNOWN
    absent = [leaf for leaf in _leaves(trace) if leaf.field == f"context.{field}"]
    assert absent
    assert all(
        leaf.absence == "absent" and "actual" not in leaf.model_fields_set for leaf in absent
    )


@pytest.mark.parametrize("reverse_creation", [False, True])
def test_temporary_yaml_multi_matches_are_id_ordered_and_repeatable(
    tmp_path: Path, reverse_creation: bool
) -> None:
    files = [("01.yaml", "z-integration-match"), ("nested/02.yml", "a-integration-match")]
    for path, rule_id in reversed(files) if reverse_creation else files:
        _write_rule(tmp_path, path, _rule_yaml(rule_id))
    normalized = normalize_windows_event_xml(_xml(SECURITY_PROCESS))
    rules = load_detection_rules(tmp_path)
    assert [rule.id for rule in rules] == ["z-integration-match", "a-integration-match"]
    matches = evaluate_event(normalized, rules)
    assert [match.rule_id for match in matches] == ["a-integration-match", "z-integration-match"]
    expected = [match.model_dump(mode="json") for match in matches]
    for _ in range(3):
        fresh_event = normalize_windows_event_xml(_xml(SECURITY_PROCESS))
        fresh_rules = load_detection_rules(tmp_path)
        assert [
            match.model_dump(mode="json") for match in evaluate_event(fresh_event, fresh_rules)
        ] == expected


@pytest.mark.parametrize("target", ["category", "source"])
def test_target_filtering_precedes_incompatible_context_evaluation(
    tmp_path: Path, target: str
) -> None:
    _write_rule(
        tmp_path,
        "filtered.yaml",
        _rule_yaml(
            category="process" if target == "category" else "authentication",
            sources="sources: [sysmon]\n" if target == "source" else "",
            condition="field: context.image\nop: ends_with\nvalue: '\\cmd.exe'\n",
        ),
    )
    normalized = normalize_windows_event_xml(_xml(SUCCESSFUL_LOGON))
    rules = load_detection_rules(tmp_path)
    assert len(rules) == 1
    # A direct evaluation would fail; the engine must filter before that boundary.
    with pytest.raises(InvalidDetectionFieldError):
        evaluate_condition(normalized, rules[0].condition)
    assert evaluate_event(normalized, rules) == ()


@pytest.mark.parametrize(
    ("content", "category"),
    [
        pytest.param("condition: [unterminated", "invalid_yaml", id="malformed-yaml"),
        pytest.param("", "invalid_document", id="empty-document"),
        pytest.param(
            _rule_yaml().replace("categories: [process]", "categories: []"),
            "invalid_rule",
            id="invalid-schema",
        ),
        pytest.param(
            _rule_yaml(condition="field: context.image\nop: regex\nvalue: example\n"),
            "invalid_rule",
            id="unsupported-operator",
        ),
        pytest.param(
            _rule_yaml(condition="field: context.image\nop: contains_any\nvalue: []\n"),
            "invalid_rule",
            id="invalid-operand",
        ),
        pytest.param(
            _rule_yaml(condition="field: context.image.more\nop: equals\nvalue: example\n"),
            "invalid_rule",
            id="nested-field-path",
        ),
        pytest.param(
            _rule_yaml(condition="field: context.image[0]\nop: equals\nvalue: example\n"),
            "invalid_rule",
            id="indexed-field-path",
        ),
    ],
)
def test_bad_yaml_or_rule_contract_aborts_loading_with_safe_file_context(
    tmp_path: Path, content: str, category: str
) -> None:
    _write_rule(tmp_path, "a-valid.yaml", _rule_yaml("valid-integration-rule"))
    _write_rule(tmp_path, "nested/b-invalid.yaml", content)
    with pytest.raises(DetectionRuleFileError) as caught:
        load_detection_rules(tmp_path)
    assert caught.value.category == category
    assert caught.value.path == "nested/b-invalid.yaml"
    assert str(tmp_path) not in str(caught.value)
    assert "unterminated" not in str(caught.value)


def test_duplicate_yaml_rule_ids_fail_the_whole_load_even_across_versions(tmp_path: Path) -> None:
    _write_rule(tmp_path, "a.yaml", _rule_yaml("duplicate-integration-rule"))
    _write_rule(tmp_path, "nested/b.yaml", _rule_yaml("duplicate-integration-rule", version=2))
    with pytest.raises(DuplicateDetectionRuleIdError) as caught:
        load_detection_rules(tmp_path)
    assert caught.value.rule_id == "duplicate-integration-rule"
    assert caught.value.first_path == "a.yaml"
    assert caught.value.duplicate_path == "nested/b.yaml"
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize(
    ("condition", "error_type", "field"),
    [
        (
            "field: context.nonexistent_field\nop: equals\nvalue: example\n",
            InvalidDetectionFieldError,
            "context.nonexistent_field",
        ),
        (
            'field: event_id\nop: contains\nvalue: "46"\n',
            IncompatibleDetectionConditionError,
            "event_id",
        ),
    ],
)
def test_loaded_semantic_errors_abort_evaluation_without_partial_matches(
    tmp_path: Path,
    condition: str,
    error_type: type[InvalidDetectionFieldError | IncompatibleDetectionConditionError],
    field: str,
) -> None:
    _write_rule(tmp_path, "a.yaml", _rule_yaml("a-valid-match"))
    _write_rule(tmp_path, "b.yaml", _rule_yaml("b-semantic-error", condition=condition))
    normalized = normalize_windows_event_xml(_xml(SECURITY_PROCESS))
    rules = load_detection_rules(tmp_path)
    assert [rule.id for rule in rules] == ["a-valid-match", "b-semantic-error"]
    assert [match.rule_id for match in evaluate_event(normalized, rules[:1])] == ["a-valid-match"]
    # The valid first match must not escape when the later applicable rule fails.
    with pytest.raises(error_type) as caught:
        evaluate_event(normalized, rules)
    assert isinstance(
        caught.value, (InvalidDetectionFieldError, IncompatibleDetectionConditionError)
    )
    assert caught.value.field == field
    if isinstance(caught.value, IncompatibleDetectionConditionError):
        assert caught.value.operator == "contains"
        assert caught.value.reason == "incompatible_field_type"
    assert normalized.computer not in str(caught.value)
    assert "synthetic-fixture" not in str(caught.value)
