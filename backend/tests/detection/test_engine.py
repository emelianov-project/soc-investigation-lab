"""Offline orchestration contracts using validated synthetic in-memory objects."""

from collections.abc import Collection
from datetime import UTC, datetime
from itertools import permutations
from typing import Any, cast

import pytest
from app.detection import (
    DetectionEngineError,
    DetectionEvaluationError,
    InvalidDetectionFieldError,
    engine,
    evaluate_condition,
    evaluate_event,
)
from app.models import (
    ConditionNode,
    ConditionOutcome,
    ConditionTrace,
    DetectionMatch,
    DetectionRule,
    EventCategory,
    EventSource,
    NormalizedEvent,
)


def event(
    source: EventSource = EventSource.SYSMON,
    category: EventCategory = EventCategory.PROCESS,
    record_id: int | None = 7,
) -> NormalizedEvent:
    contexts: dict[EventCategory, dict[str, object]] = {
        EventCategory.AUTHENTICATION: {"outcome": "success", "user": "example-user"},
        EventCategory.PROCESS: {"image": "example.exe", "process_id": 42},
        EventCategory.NETWORK: {
            "source_ip": "192.0.2.10",
            "source_port": 50000,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
        },
        EventCategory.FILE: {"target_path": r"C:\Example\file.txt"},
        EventCategory.DNS: {"query_name": "example.org"},
    }
    return NormalizedEvent.model_validate(
        {
            "source": source,
            "provider": "Example-Provider",
            "event_id": 1,
            "channel": "Example/Operational",
            "timestamp": datetime(2026, 9, 26, 12, tzinfo=UTC),
            "computer": "host.example.com",
            "record_id": record_id,
            "category": category,
            "context": contexts[category],
            "source_data": {"ExampleField": "synthetic-retained-text"},
        }
    )


def leaf(field: str = "event_id", op: str = "equals", value: object = 1) -> dict[str, object]:
    return {"field": field, "op": op, "value": value}


def rule(rule_id: str = "example-rule", **changes: Any) -> DetectionRule:
    values: dict[str, Any] = {
        "id": rule_id,
        "version": 2,
        "title": "Example rule",
        "description": "Select a synthetic event.",
        "categories": ["process"],
        "condition": leaf(),
    }
    values.update(changes)
    return DetectionRule.model_validate(values)


@pytest.mark.parametrize("rules", [[], ()])
def test_empty_collection_returns_empty_tuple(rules: Collection[DetectionRule]) -> None:
    assert evaluate_event(event(), rules) == ()


@pytest.mark.parametrize("category", list(EventCategory))
def test_each_event_category_is_supported(category: EventCategory) -> None:
    matches = evaluate_event(event(category=category), [rule(categories=[category])])
    assert len(matches) == 1
    assert matches[0].event.category is category


@pytest.mark.parametrize("source", list(EventSource))
@pytest.mark.parametrize("scoped", [False, True])
def test_omitted_or_matching_source_allows_evaluation(source: EventSource, scoped: bool) -> None:
    selected = rule(sources=[source]) if scoped else rule()
    assert len(evaluate_event(event(source), [selected])) == 1


@pytest.mark.parametrize("filter_kind", ["category", "source"])
def test_inapplicable_condition_is_not_evaluated(
    filter_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = event()
    # Valid for a DNS event, but invalid on this event's process context.
    selected = rule(categories=["dns"], condition=leaf("context.query_name", value="example.org"))
    if filter_kind == "source":
        selected = rule(
            sources=["windows_security"], condition=leaf("context.image", "greater_than", 1)
        )
    with pytest.raises(DetectionEvaluationError):
        evaluate_condition(normalized, selected.condition)

    def must_not_run(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        pytest.fail("inapplicable rule reached the condition evaluator")

    monkeypatch.setattr(engine, "evaluate_condition", must_not_run)
    assert evaluate_event(normalized, [selected]) == ()


def test_multiple_categories_and_sources_use_membership() -> None:
    selected = rule(categories=["dns", "process"], sources=["windows_security", "sysmon"])
    assert len(evaluate_event(event(), [selected])) == 1


@pytest.mark.parametrize("outcome", [ConditionOutcome.FALSE, ConditionOutcome.UNKNOWN])
def test_false_and_unknown_roots_produce_no_match(outcome: ConditionOutcome) -> None:
    condition = leaf(value=2) if outcome is ConditionOutcome.FALSE else leaf("record_id", value=7)
    normalized = event(record_id=None)
    selected = rule(condition=condition)
    assert evaluate_condition(normalized, selected.condition).outcome is outcome
    assert evaluate_event(normalized, [selected]) == ()


@pytest.mark.parametrize("record_id", [7, None])
def test_true_root_retains_exact_rule_event_and_leaf_evidence(record_id: int | None) -> None:
    normalized = event(record_id=record_id)
    selected = rule()
    matches = evaluate_event(normalized, [selected])
    assert isinstance(matches, tuple) and len(matches) == 1
    matched = matches[0]
    assert isinstance(matched, DetectionMatch)
    assert (matched.rule_id, matched.rule_version, matched.rule_title) == (
        selected.id,
        selected.version,
        selected.title,
    )
    assert matched.event is normalized
    assert matched.event.model_dump() == normalized.model_dump()
    assert matched.root_outcome is ConditionOutcome.TRUE
    assert matched.trace == evaluate_condition(normalized, selected.condition)
    assert matched.trace.location == "$"
    assert (matched.trace.field, matched.trace.expected, matched.trace.actual) == ("event_id", 1, 1)
    assert set(matched.model_dump()) == {
        "rule_id",
        "rule_version",
        "rule_title",
        "event",
        "root_outcome",
        "trace",
    }


@pytest.mark.parametrize("order", list(permutations(["z-rule", "a-rule", "m-rule"])))
def test_match_and_evaluation_order_are_sorted_by_rule_id(
    order: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = [rule(rule_id) for rule_id in order]
    called: list[ConditionNode] = []

    def recording_evaluator(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        called.append(condition)
        return evaluate_condition(event, condition)

    monkeypatch.setattr(engine, "evaluate_condition", recording_evaluator)
    matches = evaluate_event(event(), rules)
    assert [matched.rule_id for matched in matches] == ["a-rule", "m-rule", "z-rule"]
    for actual, expected in zip(called, sorted(rules, key=lambda item: item.id), strict=True):
        assert actual is expected.condition
    assert [item.id for item in rules] == list(order)
    assert len(matches) == len({matched.rule_id for matched in matches}) == 3


def test_mixed_rule_outcomes_return_only_true_matches() -> None:
    rules = [
        rule("z-true"),
        rule("b-unknown", condition=leaf("context.command_line", value="example")),
        rule("a-true"),
        rule("c-false", condition=leaf(value=2)),
        rule("d-wrong-category", categories=["file"]),
        rule("e-wrong-source", sources=["windows_security"]),
    ]
    assert [match.rule_id for match in evaluate_event(event(), rules)] == ["a-true", "z-true"]


def test_dictionary_values_collection_order_does_not_affect_results() -> None:
    rules = {"z": rule("z-rule"), "a": rule("a-rule")}
    assert evaluate_event(event(), rules.values()) == evaluate_event(
        event(), tuple(reversed(list(rules.values())))
    )


def test_nested_explanation_preserves_unknown_and_absent_children() -> None:
    selected = rule(
        sources=["sysmon"],
        condition={
            "all": [
                leaf(),
                {
                    "any": [
                        leaf("source_data.Missing", value="example"),
                        leaf("context.image", value="example.exe"),
                        leaf("context.command_line", value="example"),
                    ]
                },
                {"not": leaf(value=2)},
            ]
        },
    )
    normalized = event()
    expected = evaluate_condition(normalized, selected.condition)
    trace = evaluate_event(normalized, [selected])[0].trace
    assert trace.model_dump(exclude_unset=True) == expected.model_dump(exclude_unset=True)
    assert [child.location for child in trace.children] == ["$.all[0]", "$.all[1]", "$.all[2]"]
    missing, present, absent = trace.children[1].children
    assert (missing.location, missing.outcome, missing.absence) == (
        "$.all[1].any[0]",
        ConditionOutcome.UNKNOWN,
        "missing",
    )
    assert "actual" not in missing.model_fields_set
    assert (present.expected, present.actual) == ("example.exe", "example.exe")
    assert (absent.location, absent.outcome, absent.absence) == (
        "$.all[1].any[2]",
        ConditionOutcome.UNKNOWN,
        "absent",
    )
    assert trace.children[2].children[0].location == "$.all[2].not"


def test_engine_passes_through_the_complete_evaluator_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized, selected = event(), rule()
    expected = evaluate_condition(normalized, selected.condition)

    def evaluator(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        assert event is normalized
        assert condition is selected.condition
        return expected

    monkeypatch.setattr(engine, "evaluate_condition", evaluator)
    assert evaluate_event(normalized, [selected])[0].trace is expected


@pytest.mark.parametrize("reverse", [False, True])
def test_later_evaluation_failure_raises_without_returning_earlier_match(
    reverse: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = rule("a-matches")
    bad = rule("b-fails", condition=leaf("context.unknown", value="example"))
    later = rule("c-not-reached")
    rules = [good, bad, later]
    if reverse:
        rules.reverse()
    called: list[ConditionNode] = []

    def recording_evaluator(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        called.append(condition)
        return evaluate_condition(event, condition)

    monkeypatch.setattr(engine, "evaluate_condition", recording_evaluator)
    with pytest.raises(InvalidDetectionFieldError):
        evaluate_event(event(), rules)
    assert len(called) == 2
    assert called[0] is good.condition
    assert called[1] is bad.condition


def test_applicable_error_propagates_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = DetectionEvaluationError("synthetic_evaluation_failure")

    def fail(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        raise failure

    monkeypatch.setattr(engine, "evaluate_condition", fail)
    with pytest.raises(DetectionEvaluationError) as caught:
        evaluate_event(event(), [rule()])
    assert caught.value is failure


def test_unrelated_programmer_errors_are_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        raise RuntimeError("synthetic programmer error")

    monkeypatch.setattr(engine, "evaluate_condition", fail)
    with pytest.raises(RuntimeError, match="synthetic programmer error"):
        evaluate_event(event(), [rule()])


def test_repeated_calls_preserve_all_inputs_and_have_no_cross_event_state() -> None:
    normalized = event()
    rules = [
        rule(
            "z-rule",
            categories=["process", "dns"],
            sources=["sysmon", "windows_security"],
            condition=leaf("event_id", "in", [1, 2]),
        ),
        rule("a-rule"),
    ]
    before_event = normalized.model_dump()
    before_rules = [item.model_dump() for item in rules]
    before_order = [id(item) for item in rules]
    expected = evaluate_event(normalized, rules)
    other = event(category=EventCategory.AUTHENTICATION)
    assert evaluate_event(other, rules) == ()
    for _ in range(3):
        actual = evaluate_event(normalized, rules)
        assert [match.model_dump() for match in actual] == [
            match.model_dump() for match in expected
        ]
    assert normalized.model_dump() == before_event
    assert [item.model_dump() for item in rules] == before_rules
    assert [id(item) for item in rules] == before_order
    # Mutating returned operand evidence cannot mutate a rule's membership list.
    expected[1].trace.expected.append(3)
    assert [item.model_dump() for item in rules] == before_rules


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("applicable", [False, True])
def test_duplicate_ids_fail_before_any_evaluation(
    version: int, applicable: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    categories = ["process"] if applicable else ["dns"]
    duplicate = rule(categories=categories)
    rules = [duplicate, rule(version=version, categories=categories)]

    def must_not_run(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        pytest.fail("invalid rule set reached evaluation")

    monkeypatch.setattr(engine, "evaluate_condition", must_not_run)
    with pytest.raises(DetectionEngineError) as caught:
        evaluate_event(event(), rules)
    assert caught.value.reason == "duplicate_rule_id"
    assert caught.value.rule_id == duplicate.id
    assert isinstance(caught.value, DetectionEvaluationError)


def test_repeated_same_rule_object_is_also_a_duplicate() -> None:
    selected = rule()
    with pytest.raises(DetectionEngineError, match="duplicate_rule_id"):
        evaluate_event(event(), [selected, selected])


@pytest.mark.parametrize("invalid", [None, "not-a-rule", 1, {"id": "not-parsed"}, object()])
def test_invalid_items_are_rejected_without_coercion_before_evaluation(
    invalid: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def must_not_run(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
        pytest.fail("invalid rule set reached evaluation")

    monkeypatch.setattr(engine, "evaluate_condition", must_not_run)
    rules = cast(Collection[DetectionRule], [rule(), invalid])
    with pytest.raises(DetectionEngineError, match="invalid_rule_item"):
        evaluate_event(event(), rules)


@pytest.mark.parametrize("invalid", [None, 1, object()])
def test_noncollection_input_has_a_controlled_boundary(invalid: object) -> None:
    with pytest.raises(DetectionEngineError, match="invalid_rule_collection"):
        evaluate_event(event(), cast(Collection[DetectionRule], invalid))


def test_engine_does_not_parse_event_dictionaries() -> None:
    with pytest.raises(DetectionEngineError, match="invalid_event"):
        evaluate_event(cast(NormalizedEvent, event().model_dump()), [rule()])


def test_unexpected_match_validation_failure_is_controlled_and_safe() -> None:
    # Simulate a caller bypassing validation after constructing a domain object.
    invalid = rule().model_copy(update={"version": "synthetic-private-marker"})
    with pytest.raises(DetectionEngineError) as caught:
        evaluate_event(event(), [invalid])
    assert caught.value.reason == "invalid_match"
    assert caught.value.rule_id == invalid.id
    assert "synthetic-private-marker" not in str(caught.value)
    assert "synthetic-retained-text" not in str(caught.value)
    assert "host.example.com" not in str(caught.value)
    assert caught.value.__suppress_context__
