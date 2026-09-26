"""Stateless orchestration of validated rules for one normalized event."""

from collections.abc import Collection

from pydantic import ValidationError

from app.models import ConditionOutcome, DetectionMatch, DetectionRule, NormalizedEvent

from .errors import DetectionEngineError
from .evaluator import evaluate_condition


def _ordered_rules(rules: Collection[DetectionRule]) -> list[DetectionRule]:
    """Check the whole collection before evaluating any rule; never coerce items."""
    if not isinstance(rules, Collection):
        raise DetectionEngineError("invalid_rule_collection")
    snapshot = list(rules)
    if any(not isinstance(rule, DetectionRule) for rule in snapshot):
        raise DetectionEngineError("invalid_rule_item")
    ordered = sorted(snapshot, key=lambda rule: rule.id)
    seen: set[str] = set()
    for rule in ordered:
        if rule.id in seen:
            raise DetectionEngineError("duplicate_rule_id", rule.id)
        seen.add(rule.id)
    return ordered


def evaluate_event(
    event: NormalizedEvent, rules: Collection[DetectionRule]
) -> tuple[DetectionMatch, ...]:
    """Return TRUE-only matches in ascending rule-ID order, or fail as a whole.

    Inputs must already be validated domain objects. Category and source
    targeting are checked before calling the existing condition evaluator.
    Duplicate identities and non-rule items are rejected before evaluation,
    including inapplicable rules. Evaluation errors propagate unchanged;
    previously accumulated matches are never returned after a failure.

    No input is mutated. Each match retains the supplied event and complete
    evaluator trace, without inventing metadata. These are in-memory domain
    objects, not frozen snapshots or public exports: callers must preserve
    the event and apply appropriate redaction before exporting evidence.
    """
    if not isinstance(event, NormalizedEvent):
        raise DetectionEngineError("invalid_event")
    ordered = _ordered_rules(rules)
    matches: list[DetectionMatch] = []
    for rule in ordered:
        if event.category not in rule.categories:
            continue
        if rule.sources is not None and event.source not in rule.sources:
            continue
        trace = evaluate_condition(event, rule.condition)
        if trace.outcome is not ConditionOutcome.TRUE:
            continue
        try:
            match = DetectionMatch(
                rule_id=rule.id,
                rule_version=rule.version,
                rule_title=rule.title,
                event=event,
                root_outcome=ConditionOutcome.TRUE,
                trace=trace,
            )
        except ValidationError:
            raise DetectionEngineError("invalid_match", rule.id) from None
        matches.append(match)
    return tuple(matches)
