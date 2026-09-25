"""Focused contracts for declarative detection rules and match evidence."""

from datetime import UTC, datetime
from typing import Any

import pytest
from app.models import (
    AllCondition,
    AnyCondition,
    ConditionOutcome,
    ConditionTrace,
    DetectionMatch,
    DetectionOperator,
    DetectionRule,
    EventCategory,
    EventSource,
    LeafCondition,
    NormalizedEvent,
    NotCondition,
    ProcessContext,
)
from pydantic import ValidationError


def leaf(field: str = "event_id", op: str = "equals", value: object = 4688) -> dict[str, object]:
    """Build one safe synthetic comparison."""
    return {"field": field, "op": op, "value": value}


def rule(**changes: Any) -> DetectionRule:
    """Build a rule with valid defaults and a selectable contract mutation."""
    values: dict[str, Any] = {
        "id": "example-process-rule",
        "version": 1,
        "title": "Example process rule",
        "description": "Select a synthetic process event.",
        "categories": ["process"],
        "condition": leaf(),
    }
    values.update(changes)
    return DetectionRule.model_validate(values)


def event() -> NormalizedEvent:
    """Build an already-normalized synthetic event for match evidence."""
    return NormalizedEvent(
        source=EventSource.WINDOWS_SECURITY,
        provider="Microsoft-Windows-Security-Auditing",
        event_id=4688,
        channel="Security",
        timestamp=datetime(2026, 9, 25, 12, 0, tzinfo=UTC),
        computer="host.example.com",
        record_id=7,
        category=EventCategory.PROCESS,
        context=ProcessContext(image=r"C:\Windows\System32\cmd.exe", process_id=42),
    )


def trace(**changes: Any) -> ConditionTrace:
    """Build a true leaf explanation with a stable root location."""
    values: dict[str, Any] = {
        "location": "$",
        "kind": "leaf",
        "outcome": "true",
        "field": "event_id",
        "op": "equals",
        "expected": 4688,
        "actual": 4688,
    }
    values.update(changes)
    return ConditionTrace.model_validate(values)


def test_public_detection_models_and_closed_operator_set() -> None:
    assert len(DetectionOperator) == 15
    assert {operator.value for operator in DetectionOperator} == {
        "equals",
        "not_equals",
        "contains",
        "contains_any",
        "starts_with",
        "ends_with",
        "in",
        "not_in",
        "exists",
        "not_exists",
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
        "ip_in_cidr",
    }
    assert {outcome.value for outcome in ConditionOutcome} == {"true", "false", "unknown"}
    assert isinstance(rule().condition, LeafCondition)


def test_nested_rule_preserves_order_and_node_shapes() -> None:
    condition = {
        "all": [
            leaf(),
            {
                "any": [
                    leaf("context.image", "ends_with", r"\cmd.exe"),
                    {"not": leaf("computer", "equals", "other.example.com")},
                ]
            },
        ]
    }
    parsed = rule(condition=condition)
    assert isinstance(parsed.condition, AllCondition)
    assert isinstance(parsed.condition.all[1], AnyCondition)
    assert isinstance(parsed.condition.all[1].any[1], NotCondition)
    assert parsed.model_dump(by_alias=True, exclude_unset=True)["condition"] == condition


@pytest.mark.parametrize(
    ("operator", "value"),
    [
        ("equals", "example"),
        ("not_equals", 7),
        ("contains", "exam"),
        ("contains_any", ["exam", "other"]),
        ("starts_with", "ex"),
        ("ends_with", "ple"),
        ("in", [1, 2]),
        ("not_in", ["a", "b"]),
        ("greater_than", 1),
        ("greater_or_equal", 1),
        ("less_than", 3),
        ("less_or_equal", 3),
        ("ip_in_cidr", "192.0.2.0/24"),
    ],
)
def test_operators_accept_their_structural_operand_shape(operator: str, value: object) -> None:
    assert isinstance(
        rule(condition=leaf("context.image", operator, value)).condition, LeafCondition
    )


@pytest.mark.parametrize("operator", ["exists", "not_exists"])
def test_existence_operators_require_omitted_value(operator: str) -> None:
    assert isinstance(
        rule(condition={"field": "record_id", "op": operator}).condition, LeafCondition
    )
    with pytest.raises(ValidationError):
        rule(condition={"field": "record_id", "op": operator, "value": None})


@pytest.mark.parametrize(
    "condition",
    [
        leaf(op="regex"),
        leaf(value=None),
        leaf(value=True),
        leaf(op="contains", value=1),
        leaf(op="contains_any", value=[]),
        leaf(op="contains_any", value=["a", 1]),
        leaf(op="in", value=[]),
        leaf(op="in", value=[1, "1"]),
        leaf(op="in", value=[True]),
        leaf(op="greater_than", value="1"),
        leaf(op="greater_than", value=True),
        leaf(op="ip_in_cidr", value=1),
        {"field": "event_id", "op": "equals"},
        {"field": "event_id", "op": "equals", "value": 1, "extra": True},
        {"all": []},
        {"any": []},
        {"not": [leaf(), leaf()]},
        {"all": [leaf()], "any": [leaf()]},
    ],
)
def test_invalid_condition_shapes_are_rejected(condition: object) -> None:
    with pytest.raises(ValidationError):
        rule(condition=condition)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "unknown",
        "Context.image",
        "context",
        "context.image.more",
        "context.image[0]",
        "context.*",
        "context.image()",
        "context._private",
        "source_data",
        "source_data.1Field",
        "source_data.Name.more",
        "source_data.[0]",
        "source_data.Name()",
        "provider.lower",
        "__class__",
    ],
)
def test_field_paths_reject_expressions_and_traversal(path: str) -> None:
    with pytest.raises(ValidationError):
        rule(condition=leaf(path))


@pytest.mark.parametrize(
    "path",
    [
        "source",
        "provider",
        "event_id",
        "channel",
        "timestamp",
        "computer",
        "record_id",
        "category",
        "context.image",
        "source_data.CommandLine",
    ],
)
def test_allowed_field_path_syntax(path: str) -> None:
    kwargs: dict[str, Any] = {"condition": leaf(path)}
    if path.startswith("source_data."):
        kwargs["sources"] = ["windows_security"]
    assert isinstance(rule(**kwargs).condition, LeafCondition)


@pytest.mark.parametrize(
    "bad_id", ["", "Upper", "bad_underscore", "-start", "end-", "two--hyphens", "has space"]
)
def test_rule_id_requires_stable_slug(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        rule(id=bad_id)


@pytest.mark.parametrize("bad_version", [0, -1, True, "1", 1.5])
def test_rule_version_requires_positive_strict_integer(bad_version: object) -> None:
    with pytest.raises(ValidationError):
        rule(version=bad_version)


@pytest.mark.parametrize("field", ["title", "description"])
@pytest.mark.parametrize("value", ["", "   ", None, 7])
def test_rule_text_is_nonempty_strict_string(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        rule(**{field: value})


@pytest.mark.parametrize(
    "categories",
    [[], ["process", "process"], ["unknown"], [1], None],
)
def test_categories_are_nonempty_unique_and_supported(categories: object) -> None:
    with pytest.raises(ValidationError):
        rule(categories=categories)


@pytest.mark.parametrize(
    "sources",
    [[], ["sysmon", "sysmon"], ["unknown"], [1], None],
)
def test_sources_when_declared_are_nonempty_unique_and_supported(sources: object) -> None:
    with pytest.raises(ValidationError):
        rule(sources=sources)


def test_source_data_requires_source_scope_even_when_nested() -> None:
    scoped = {"all": [leaf(), {"not": leaf("source_data.Image", "equals", "example")}]}
    with pytest.raises(ValidationError):
        rule(condition=scoped)
    assert rule(condition=scoped, sources=["sysmon"]).sources == [EventSource.SYSMON]


def test_maximum_depth_is_eight_nodes() -> None:
    at_limit: dict[str, object] = leaf()
    for _ in range(7):
        at_limit = {"not": at_limit}
    assert isinstance(rule(condition=at_limit).condition, NotCondition)
    with pytest.raises(ValidationError):
        rule(condition={"not": at_limit})


def test_maximum_leaf_count_is_sixty_four() -> None:
    at_limit = rule(condition={"all": [leaf()] * 64}).condition
    assert isinstance(at_limit, AllCondition)
    assert len(at_limit.all) == 64
    with pytest.raises(ValidationError):
        rule(condition={"all": [leaf()] * 65})


def test_extra_rule_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        rule(severity="high")


def test_trace_preserves_order_and_safe_leaf_evidence() -> None:
    child = trace(location="$.all[0]")
    root = ConditionTrace(location="$", kind="all", outcome=ConditionOutcome.TRUE, children=[child])
    assert root.children[0].field == "event_id"
    assert root.children[0].expected == 4688
    assert root.children[0].actual == 4688


def test_trace_can_mark_missing_absent_and_redacted_values() -> None:
    for absence in ("missing", "absent"):
        explained = ConditionTrace(
            location="$",
            kind="leaf",
            outcome=ConditionOutcome.UNKNOWN,
            field="source_data.Image",
            op=DetectionOperator.EQUALS,
            expected="example",
            absence=absence,
        )
        assert explained.absence == absence
        assert "actual" not in explained.model_fields_set
    explained = ConditionTrace(
        location="$",
        kind="leaf",
        outcome=ConditionOutcome.TRUE,
        field="source_data.Image",
        op=DetectionOperator.EQUALS,
        expected="example",
        redacted=True,
        redaction_marker="[REDACTED]",
    )
    assert explained.redacted and explained.redaction_marker == "[REDACTED]"


def test_trace_rejects_unsafe_actual_values_and_wrong_child_location() -> None:
    for actual in (None, ["value"], {"private": "value"}, object()):
        with pytest.raises(ValidationError):
            trace(actual=actual)
    with pytest.raises(ValidationError):
        ConditionTrace(
            location="$",
            kind="all",
            outcome=ConditionOutcome.TRUE,
            children=[trace(location="$.any[0]")],
        )


def test_condition_collections_reject_nonlist_input() -> None:
    with pytest.raises(ValidationError):
        rule(categories=("process",))
    with pytest.raises(ValidationError):
        rule(condition={"all": (leaf(),)})


@pytest.mark.parametrize(
    "changes",
    [
        {"location": "$.all[-1]"},
        {"kind": "leaf", "children": [trace()]},
        {"field": None},
        {"op": None},
        {"redacted": True},
        {"redaction_marker": "[REDACTED]"},
        {"absence": "missing"},
        {"extra": 1},
    ],
)
def test_invalid_trace_evidence_is_rejected(changes: dict[str, object]) -> None:
    if changes == {"absence": "missing"}:
        changes = {**changes, "actual": 4688}
    with pytest.raises(ValidationError):
        trace(**changes)


def test_match_requires_true_root_and_keeps_event_identity() -> None:
    matched = DetectionMatch(
        rule_id="example-process-rule",
        rule_version=1,
        rule_title="Example process rule",
        event=event(),
        root_outcome=ConditionOutcome.TRUE,
        trace=trace(),
    )
    assert matched.event.record_id == 7
    assert matched.trace.location == "$"


@pytest.mark.parametrize("root_outcome", ["false", "unknown"])
def test_false_or_unknown_root_cannot_be_a_match(root_outcome: str) -> None:
    with pytest.raises(ValidationError):
        DetectionMatch.model_validate(
            {
                "rule_id": "example-process-rule",
                "rule_version": 1,
                "rule_title": "Example process rule",
                "event": event(),
                "root_outcome": root_outcome,
                "trace": trace(),
            }
        )


def test_match_rejects_nonroot_or_untrue_trace_and_extra_fields() -> None:
    base = {
        "rule_id": "example-process-rule",
        "rule_version": 1,
        "rule_title": "Example process rule",
        "event": event(),
        "root_outcome": "true",
    }
    with pytest.raises(ValidationError):
        DetectionMatch.model_validate({**base, "trace": trace(location="$.not")})
    with pytest.raises(ValidationError):
        DetectionMatch.model_validate({**base, "trace": trace(outcome="unknown")})
    with pytest.raises(ValidationError):
        DetectionMatch.model_validate({**base, "trace": trace(), "alert": {}})
