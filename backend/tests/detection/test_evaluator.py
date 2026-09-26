"""Synthetic, offline contracts for single-event condition evaluation."""

from datetime import UTC, datetime
from ipaddress import ip_address
from itertools import product
from typing import Any

import pytest
from app.detection import (
    DetectionEvaluationError,
    FieldPresence,
    FieldType,
    IncompatibleDetectionConditionError,
    InvalidDetectionFieldError,
    evaluate_condition,
    resolve_event_field,
)
from app.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    ConditionOutcome,
    ConditionTrace,
    DetectionOperator,
    LeafCondition,
    NormalizedEvent,
    NotCondition,
)

CONTEXTS: dict[str, dict[str, object]] = {
    "authentication": {
        "outcome": "success",
        "user": "example-user",
        "domain": "example.com",
        "logon_type": 3,
        "source_ip": "192.0.2.10",
        "source_port": 50000,
        "workstation": "host.example.com",
    },
    "process": {
        "image": "PowerShell.exe",
        "process_id": 42,
        "command_line": "example-command",
        "parent_process_id": 7,
        "parent_image": "example-parent.exe",
        "user": "example-user",
    },
    "network": {
        "source_ip": "192.0.2.10",
        "source_port": 50000,
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "protocol": "tcp",
        "process_id": 42,
        "process_image": "example.exe",
    },
    "file": {
        "target_path": r"C:\Example\file.txt",
        "process_id": 42,
        "process_image": "example.exe",
    },
    "dns": {
        "query_name": "example.org",
        "query_status": "0",
        "query_results": "203.0.113.10",
        "process_id": 42,
        "process_image": "example.exe",
    },
}


def event(category: str = "process", **context_changes: Any) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "source": "windows_security" if category == "authentication" else "sysmon",
            "provider": "Example-Provider",
            "event_id": 1,
            "channel": "Example/Operational",
            "timestamp": "2026-09-26T12:00:00Z",
            "computer": "host.example.com",
            "record_id": 7,
            "category": category,
            "context": {**CONTEXTS[category], **context_changes},
            "source_data": {"ExampleField": "1", "Empty": "", "Address": "2001:db8::1"},
        }
    )


def leaf(field: str, op: str = "equals", value: object = 1) -> LeafCondition:
    values = {"field": field, "op": op}
    if op not in {"exists", "not_exists"}:
        return LeafCondition.model_validate({**values, "value": value})
    return LeafCondition.model_validate(values)


@pytest.mark.parametrize(
    ("field", "expected", "field_type"),
    [
        ("source", "sysmon", FieldType.STRING),
        ("provider", "Example-Provider", FieldType.STRING),
        ("event_id", 1, FieldType.INTEGER),
        ("channel", "Example/Operational", FieldType.STRING),
        ("timestamp", datetime(2026, 9, 26, 12, tzinfo=UTC), FieldType.TIMESTAMP),
        ("computer", "host.example.com", FieldType.STRING),
        ("record_id", 7, FieldType.INTEGER),
        ("category", "process", FieldType.STRING),
        ("source_data.ExampleField", "1", FieldType.STRING),
        ("source_data.Empty", "", FieldType.STRING),
    ],
)
def test_common_and_source_fields(field: str, expected: object, field_type: FieldType) -> None:
    result = resolve_event_field(event(), field)
    assert result.path == field
    assert result.presence is FieldPresence.PRESENT
    assert result.field_type is field_type
    assert result.value == expected
    assert type(result.value) is type(expected)


@pytest.mark.parametrize(
    ("category", "name", "expected"),
    [
        (category, name, value)
        for category, fields in CONTEXTS.items()
        for name, value in fields.items()
    ],
)
def test_every_declared_context_field(category: str, name: str, expected: object) -> None:
    result = resolve_event_field(event(category), f"context.{name}")
    if name in {"source_ip", "destination_ip"}:
        assert isinstance(expected, str)
        expected = ip_address(expected)
        assert result.field_type is FieldType.IP
    elif type(expected) is int:
        assert result.field_type is FieldType.INTEGER
    else:
        assert result.field_type is FieldType.STRING
    assert result.presence is FieldPresence.PRESENT
    assert result.value == expected
    assert type(result.value) is type(expected)


def test_absent_and_missing_are_distinct_and_keep_the_declared_type() -> None:
    normalized = event("authentication", user=None, source_ip=None, logon_type=None)
    normalized.record_id = None
    for field, expected_type in [
        ("context.user", FieldType.STRING),
        ("context.source_ip", FieldType.IP),
        ("context.logon_type", FieldType.INTEGER),
        ("record_id", FieldType.INTEGER),
    ]:
        result = resolve_event_field(normalized, field)
        assert result.presence is FieldPresence.ABSENT
        assert result.value is None
        assert result.field_type is expected_type
    missing = resolve_event_field(normalized, "source_data.Missing")
    assert missing.presence is FieldPresence.MISSING
    assert missing.value is None
    assert missing.field_type is FieldType.STRING


@pytest.mark.parametrize(
    "field",
    [
        "",
        "unknown",
        "Provider",
        "context",
        "context.unknown",
        "context.query_name",
        "context.__class__",
        "context.image.more",
        "context.image[0]",
        "context.*",
        "context.image()",
        "provider.lower",
        "__class__",
        "source_data",
        "source_data.",
        "source_data.1Field",
        "source_data._private",
        "source_data.Name.more",
        "source_data.Name()",
        "source_data.Name[0]",
        "source_data.*",
        "source_data.Éxample",
    ],
)
def test_invalid_paths_never_mean_missing_or_traverse_objects(field: str) -> None:
    with pytest.raises(InvalidDetectionFieldError) as caught:
        resolve_event_field(event(), field)
    assert caught.value.field == field
    assert isinstance(caught.value, DetectionEvaluationError)


@pytest.mark.parametrize("category", list(CONTEXTS))
def test_other_contexts_cannot_resolve_process_image_field(category: str) -> None:
    if category == "process":
        assert resolve_event_field(event(category), "context.image").value == "PowerShell.exe"
    else:
        with pytest.raises(InvalidDetectionFieldError):
            evaluate_condition(event(category), leaf("context.image", "exists"))


@pytest.mark.parametrize(
    ("op", "positive", "negative"),
    [
        ("equals", "PowerShell.exe", "powershell.exe"),
        ("not_equals", "powershell.exe", "PowerShell.exe"),
        ("contains", "Shell", "shell"),
        ("contains_any", ["other", "Shell"], ["other", "shell"]),
        ("starts_with", "Power", "power"),
        ("ends_with", "Shell.exe", "shell.exe"),
        ("in", ["other", "PowerShell.exe"], ["Power", "powershell.exe"]),
        ("not_in", ["Power", "powershell.exe"], ["other", "PowerShell.exe"]),
    ],
)
def test_string_operators_are_exact_and_case_sensitive(
    op: str, positive: object, negative: object
) -> None:
    assert (
        evaluate_condition(event(), leaf("context.image", op, positive)).outcome
        is ConditionOutcome.TRUE
    )
    assert (
        evaluate_condition(event(), leaf("context.image", op, negative)).outcome
        is ConditionOutcome.FALSE
    )


@pytest.mark.parametrize(
    ("op", "value", "expected"),
    [
        ("equals", 42, True),
        ("equals", 41, False),
        ("not_equals", 41, True),
        ("not_equals", 42, False),
        ("in", [41, 42], True),
        ("in", [40, 41], False),
        ("not_in", [40, 41], True),
        ("not_in", [41, 42], False),
        ("greater_than", 41, True),
        ("greater_than", 42, False),
        ("greater_or_equal", 42, True),
        ("greater_or_equal", 43, False),
        ("less_than", 43, True),
        ("less_than", 42, False),
        ("less_or_equal", 42, True),
        ("less_or_equal", 41, False),
    ],
)
def test_integer_comparisons_and_boundaries(op: str, value: object, expected: bool) -> None:
    trace = evaluate_condition(event(), leaf("context.process_id", op, value))
    assert trace.outcome is (ConditionOutcome.TRUE if expected else ConditionOutcome.FALSE)


@pytest.mark.parametrize(
    ("category", "field", "expected"),
    [
        ("process", "source", "sysmon"),
        ("authentication", "source", "windows_security"),
        ("process", "category", "process"),
        ("authentication", "context.outcome", "success"),
    ],
)
def test_enums_use_declared_string_values(category: str, field: str, expected: str) -> None:
    for op, value in [("equals", expected), ("in", ["other", expected])]:
        trace = evaluate_condition(event(category), leaf(field, op, value))
        assert trace.outcome is ConditionOutcome.TRUE
        assert type(trace.actual) is str
    assert (
        evaluate_condition(event(category), leaf(field, "equals", expected.upper())).outcome
        is ConditionOutcome.FALSE
    )


STRING_COMPARISONS: list[tuple[str, object]] = [
    ("equals", "text"),
    ("not_equals", "text"),
    ("contains", "text"),
    ("contains_any", ["text"]),
    ("starts_with", "text"),
    ("ends_with", "text"),
    ("in", ["text"]),
    ("not_in", ["text"]),
]


@pytest.mark.parametrize(("op", "value"), STRING_COMPARISONS)
@pytest.mark.parametrize("field", ["source_data.Missing", "context.command_line"])
def test_missing_and_absent_string_comparisons_are_unknown(
    field: str, op: str, value: object
) -> None:
    trace = evaluate_condition(event(command_line=None), leaf(field, op, value))
    assert trace.outcome is ConditionOutcome.UNKNOWN
    assert trace.absence == ("missing" if field.startswith("source_data") else "absent")
    assert "actual" not in trace.model_fields_set
    assert trace.expected == value


@pytest.mark.parametrize("field", ["source_data.Missing", "context.command_line", "record_id"])
@pytest.mark.parametrize(
    ("op", "outcome"), [("exists", ConditionOutcome.FALSE), ("not_exists", ConditionOutcome.TRUE)]
)
def test_missing_and_absent_existence(field: str, op: str, outcome: ConditionOutcome) -> None:
    normalized = event(command_line=None)
    normalized.record_id = None
    trace = evaluate_condition(normalized, leaf(field, op))
    assert trace.outcome is outcome
    assert "actual" not in trace.model_fields_set
    assert "expected" not in trace.model_fields_set


@pytest.mark.parametrize("field", ["source_data.Empty", "context.process_id", "record_id"])
@pytest.mark.parametrize(
    ("op", "outcome"), [("exists", ConditionOutcome.TRUE), ("not_exists", ConditionOutcome.FALSE)]
)
def test_present_empty_string_and_zero_are_not_absent(
    field: str, op: str, outcome: ConditionOutcome
) -> None:
    normalized = event(process_id=0)
    normalized.record_id = 0
    trace = evaluate_condition(normalized, leaf(field, op))
    assert trace.outcome is outcome
    assert trace.absence is None
    assert "expected" not in trace.model_fields_set


@pytest.mark.parametrize("field", ["record_id", "context.process_id"])
@pytest.mark.parametrize(
    "op",
    [
        "equals",
        "not_equals",
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
        "in",
        "not_in",
    ],
)
def test_absent_integer_comparisons_remain_unknown(field: str, op: str) -> None:
    normalized = event(process_id=None)
    normalized.record_id = None
    trace = evaluate_condition(normalized, leaf(field, op, [1] if op in {"in", "not_in"} else 1))
    assert trace.outcome is ConditionOutcome.UNKNOWN
    assert trace.absence == "absent"


@pytest.mark.parametrize("op", ["equals", "not_equals", "in", "not_in", "ip_in_cidr"])
def test_absent_ip_comparisons_remain_unknown(op: str) -> None:
    value: object = "192.0.2.0/24" if op == "ip_in_cidr" else "192.0.2.10"
    if op in {"in", "not_in"}:
        value = [value]
    trace = evaluate_condition(
        event("authentication", source_ip=None), leaf("context.source_ip", op, value)
    )
    assert trace.outcome is ConditionOutcome.UNKNOWN
    assert trace.absence == "absent"


@pytest.mark.parametrize(
    ("field", "op", "value"),
    [
        ("event_id", "equals", "1"),
        ("source_data.ExampleField", "equals", 1),
        ("event_id", "in", ["1"]),
        ("event_id", "contains", "1"),
        ("event_id", "contains_any", ["1"]),
        ("event_id", "starts_with", "1"),
        ("record_id", "ends_with", "7"),
        ("context.image", "greater_than", 1),
        ("source_data.ExampleField", "greater_or_equal", 1),
        ("source_data.Missing", "less_than", 1),
        ("source_data.Missing", "less_or_equal", 1),
        ("context.image", "ip_in_cidr", "192.0.2.0/24"),
        ("source_data.Address", "ip_in_cidr", "2001:db8::/32"),
        ("timestamp", "greater_than", 1),
        ("timestamp", "contains", "2026"),
        ("timestamp", "equals", "2026-09-26T12:00:00"),
        ("timestamp", "equals", "invalid"),
        ("timestamp", "in", ["2026-09-26T12:00:00Z", "invalid"]),
        ("context.command_line", "greater_than", 1),
    ],
)
def test_incompatible_conditions_raise_safe_errors(field: str, op: str, value: object) -> None:
    with pytest.raises(IncompatibleDetectionConditionError) as caught:
        evaluate_condition(event(command_line=None), leaf(field, op, value))
    assert caught.value.field == field
    assert caught.value.operator == op
    assert "Example-Provider" not in str(caught.value)
    assert "host.example.com" not in str(caught.value)


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("equals", True),
        ("in", [True]),
        ("in", [1, "1"]),
        ("greater_than", True),
        ("contains_any", []),
        ("in", []),
    ],
)
def test_unexpected_runtime_operands_are_not_coerced(op: str, value: object) -> None:
    # Exercise the defensive boundary with a model whose validation was bypassed.
    field = "context.image" if op == "contains_any" else "event_id"
    condition = leaf("event_id").model_copy(
        update={"field": field, "op": DetectionOperator(op), "value": value}
    )
    with pytest.raises(IncompatibleDetectionConditionError):
        evaluate_condition(event(), condition)


@pytest.mark.parametrize("value", [True, "1"])
def test_unexpected_actual_integer_type_is_controlled(value: object) -> None:
    normalized = event().model_copy(update={"event_id": value})
    with pytest.raises(IncompatibleDetectionConditionError, match="invalid_actual_type"):
        evaluate_condition(normalized, leaf("event_id"))


@pytest.mark.parametrize(
    ("address", "cidr", "expected"),
    [
        ("192.0.2.10", "192.0.2.0/24", True),
        ("198.51.100.10", "192.0.2.0/24", False),
        ("2001:db8::10", "2001:db8::/32", True),
        ("2001:db8:1::10", "2001:db8:2::/48", False),
        ("192.0.2.10", "2001:db8::/32", False),
        ("2001:db8::10", "192.0.2.0/24", False),
    ],
)
def test_cidr_uses_typed_address_families(address: str, cidr: str, expected: bool) -> None:
    trace = evaluate_condition(
        event("authentication", source_ip=address), leaf("context.source_ip", "ip_in_cidr", cidr)
    )
    assert trace.outcome is (ConditionOutcome.TRUE if expected else ConditionOutcome.FALSE)
    assert trace.actual == ip_address(address)


@pytest.mark.parametrize("address", ["192.0.2.10", "2001:db8::10"])
@pytest.mark.parametrize("op", ["equals", "not_equals", "in", "not_in"])
@pytest.mark.parametrize("matches", [True, False])
def test_typed_ip_equality_and_membership(address: str, op: str, matches: bool) -> None:
    literal = address if matches else "203.0.113.20"
    if address.startswith("2001") and matches:
        literal = "2001:0db8:0000:0000:0000:0000:0000:0010"
    value: object = [literal] if op in {"in", "not_in"} else literal
    trace = evaluate_condition(
        event("authentication", source_ip=address), leaf("context.source_ip", op, value)
    )
    expected = matches if op in {"equals", "in"} else not matches
    assert trace.outcome is (ConditionOutcome.TRUE if expected else ConditionOutcome.FALSE)


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("ip_in_cidr", "invalid-cidr"),
        ("ip_in_cidr", "192.0.2.0/99"),
        ("equals", "invalid-ip"),
        ("in", ["192.0.2.10", "invalid-ip"]),
    ],
)
def test_invalid_ip_operands_are_controlled_without_content_leak(op: str, value: object) -> None:
    with pytest.raises(IncompatibleDetectionConditionError) as caught:
        evaluate_condition(event("authentication"), leaf("context.source_ip", op, value))
    assert "invalid-ip" not in str(caught.value)
    assert "invalid-cidr" not in str(caught.value)


@pytest.mark.parametrize("op", ["equals", "not_equals", "in", "not_in"])
@pytest.mark.parametrize("matches", [True, False])
def test_timestamp_literals_compare_utc_instants(op: str, matches: bool) -> None:
    literal = "2026-09-26T15:00:00+03:00" if matches else "2026-09-26T12:00:01Z"
    value: object = [literal] if op in {"in", "not_in"} else literal
    trace = evaluate_condition(event(), leaf("timestamp", op, value))
    expected = matches if op in {"equals", "in"} else not matches
    assert trace.outcome is (ConditionOutcome.TRUE if expected else ConditionOutcome.FALSE)
    assert trace.actual == event().timestamp
    assert trace.expected == value


def test_string_values_are_not_normalized_or_interpreted() -> None:
    for actual, expected in [
        ("é", "e\u0301"),
        (r"C:\Example\file", "C:/Example/file"),
        ("host.example.com", "HOST.EXAMPLE.COM"),
    ]:
        assert (
            evaluate_condition(
                event(image=actual), leaf("context.image", "equals", expected)
            ).outcome
            is ConditionOutcome.FALSE
        )
    normalized = event()
    assert (
        evaluate_condition(normalized, leaf("source_data.ExampleField", "equals", "1")).outcome
        is ConditionOutcome.TRUE
    )
    assert (
        evaluate_condition(
            normalized, leaf("source_data.Address", "equals", "2001:0db8::1")
        ).outcome
        is ConditionOutcome.FALSE
    )
    inert = "example_callback()"
    assert (
        evaluate_condition(
            event(command_line=inert), leaf("context.command_line", "equals", inert)
        ).outcome
        is ConditionOutcome.TRUE
    )


def outcome_leaf(outcome: ConditionOutcome) -> LeafCondition:
    if outcome is ConditionOutcome.UNKNOWN:
        return leaf("source_data.Missing", value="example")
    return leaf("event_id", value=1 if outcome is ConditionOutcome.TRUE else 2)


@pytest.mark.parametrize(("left", "right"), list(product(ConditionOutcome, repeat=2)))
@pytest.mark.parametrize("kind", ["all", "any"])
def test_complete_three_valued_truth_tables(
    kind: str, left: ConditionOutcome, right: ConditionOutcome
) -> None:
    children: list[ConditionNode] = [outcome_leaf(left), outcome_leaf(right)]
    condition = AllCondition(all=children) if kind == "all" else AnyCondition(any=children)
    trace = evaluate_condition(event(), condition)
    true, false, unknown = ConditionOutcome.TRUE, ConditionOutcome.FALSE, ConditionOutcome.UNKNOWN
    all_table = {
        (true, true): true,
        (true, false): false,
        (true, unknown): unknown,
        (false, true): false,
        (false, false): false,
        (false, unknown): false,
        (unknown, true): unknown,
        (unknown, false): false,
        (unknown, unknown): unknown,
    }
    any_table = {
        (true, true): true,
        (true, false): true,
        (true, unknown): true,
        (false, true): true,
        (false, false): false,
        (false, unknown): unknown,
        (unknown, true): true,
        (unknown, false): unknown,
        (unknown, unknown): unknown,
    }
    assert trace.outcome is (all_table if kind == "all" else any_table)[left, right]
    assert trace.kind == kind
    assert [child.outcome for child in trace.children] == [left, right]
    assert [child.location for child in trace.children] == [f"$.{kind}[0]", f"$.{kind}[1]"]


@pytest.mark.parametrize(
    ("child", "expected"),
    [
        (ConditionOutcome.TRUE, ConditionOutcome.FALSE),
        (ConditionOutcome.FALSE, ConditionOutcome.TRUE),
        (ConditionOutcome.UNKNOWN, ConditionOutcome.UNKNOWN),
    ],
)
def test_not_preserves_unknown(child: ConditionOutcome, expected: ConditionOutcome) -> None:
    condition = NotCondition.model_validate({"not": outcome_leaf(child)})
    trace = evaluate_condition(event(), condition)
    assert trace.kind == "not"
    assert trace.outcome is expected
    assert len(trace.children) == 1
    assert trace.children[0].location == "$.not"
    assert trace.children[0].outcome is child


@pytest.mark.parametrize("kind", ["all", "any"])
def test_decisive_first_child_does_not_hide_later_errors(kind: str) -> None:
    first = outcome_leaf(ConditionOutcome.FALSE if kind == "all" else ConditionOutcome.TRUE)
    children: list[ConditionNode] = [first, leaf("context.unknown", "exists")]
    condition = AllCondition(all=children) if kind == "all" else AnyCondition(any=children)
    with pytest.raises(InvalidDetectionFieldError):
        evaluate_condition(event(), condition)


def test_nested_trace_is_complete_ordered_deterministic_and_nonmutating() -> None:
    normalized = event()
    condition = AllCondition.model_validate(
        {
            "all": [
                leaf("event_id", value=2),
                {"any": [leaf("event_id"), {"not": leaf("source_data.Missing", value="example")}]},
                leaf("context.image", "in", ["PowerShell.exe", "example.exe"]),
            ]
        }
    )
    before_event = normalized.model_dump()
    before_condition = condition.model_dump()
    trace = evaluate_condition(normalized, condition)
    assert isinstance(trace, ConditionTrace)
    assert trace == evaluate_condition(normalized, condition)
    assert trace.outcome is ConditionOutcome.FALSE
    assert [child.location for child in trace.children] == ["$.all[0]", "$.all[1]", "$.all[2]"]
    nested = trace.children[1]
    assert nested.outcome is ConditionOutcome.TRUE
    assert [child.location for child in nested.children] == ["$.all[1].any[0]", "$.all[1].any[1]"]
    assert nested.children[1].children[0].location == "$.all[1].any[1].not"
    assert nested.children[1].children[0].absence == "missing"
    first = trace.children[0]
    assert (first.field, first.op, first.expected, first.actual) == (
        "event_id",
        DetectionOperator.EQUALS,
        2,
        1,
    )
    assert normalized.model_dump() == before_event
    assert condition.model_dump() == before_condition
    trace.children[2].expected.append("other.exe")
    assert condition.model_dump() == before_condition


def test_controlled_error_does_not_include_retained_text_or_raw_exception() -> None:
    normalized = event()
    normalized.source_data["ExampleField"] = "synthetic-private-marker"
    with pytest.raises(DetectionEvaluationError) as caught:
        evaluate_condition(normalized, leaf("source_data.ExampleField", "greater_than", 1))
    assert "synthetic-private-marker" not in str(caught.value)
    assert "Traceback" not in str(caught.value)
