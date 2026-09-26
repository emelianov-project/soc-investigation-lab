"""Explicit, in-memory evaluation of one condition tree against one event."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Literal, cast

from app.models import (
    AllCondition,
    AnyCondition,
    AuthenticationOutcome,
    ConditionNode,
    ConditionOutcome,
    ConditionTrace,
    DetectionOperator,
    EventCategory,
    EventContext,
    EventSource,
    LeafCondition,
    NormalizedEvent,
    NotCondition,
)

from .errors import (
    DetectionEvaluationError,
    IncompatibleDetectionConditionError,
)
from .semantics import (
    EXISTENCE_OPERATORS,
    FieldType,
    Operand,
    Scalar,
    context_type,
    field_type,
    validated_operands,
)


class FieldPresence(StrEnum):
    """Missing retained text is distinct from an absent declared field."""

    PRESENT = "present"
    MISSING = "missing"
    ABSENT = "absent"


@dataclass(frozen=True)
class ResolvedField:
    """A whitelisted field with its declared type and explicit presence state."""

    path: str
    field_type: FieldType
    presence: FieldPresence
    value: Scalar | None


def _resolved(path: str, field_type: FieldType, value: Scalar | None) -> ResolvedField:
    if value is None:
        return ResolvedField(path, field_type, FieldPresence.ABSENT, None)
    if isinstance(value, (EventSource, EventCategory, AuthenticationOutcome)):
        value = value.value
    valid = (
        (field_type is FieldType.STRING and type(value) is str)
        or (field_type is FieldType.INTEGER and type(value) is int)
        or (field_type is FieldType.IP and isinstance(value, (IPv4Address, IPv6Address)))
        or (
            field_type is FieldType.TIMESTAMP
            and isinstance(value, datetime)
            and value.utcoffset() is not None
        )
    )
    if not valid:
        raise IncompatibleDetectionConditionError(path, "resolve", "invalid_actual_type")
    return ResolvedField(path, field_type, FieldPresence.PRESENT, value)


def resolve_event_field(event: NormalizedEvent, field_path: str) -> ResolvedField:
    """Resolve a closed path without coercion, traversal, or fallback.

    Enum-backed fields expose their declared string values. A context field
    must belong to this event's actual typed context; an invalid path is never
    treated as missing. Retained source_data is text, not a typed fallback.
    """
    kind = field_type(field_path, event.category)
    if field_path.startswith("source_data."):
        name = field_path.split(".")[1]
        if name not in event.source_data:
            return ResolvedField(field_path, kind, FieldPresence.MISSING, None)
        return _resolved(field_path, kind, event.source_data[name])
    model: NormalizedEvent | EventContext = event
    name = field_path
    if field_path.startswith("context."):
        if not isinstance(event.context, context_type(event.category)):
            raise DetectionEvaluationError("invalid_context_type")
        model = event.context
        name = field_path.split(".")[1]
    # The shared allowlist has already accepted this single declared data field.
    # Python-mode extraction retains IP/datetime/enum types, with no attribute traversal.
    try:
        value = model.model_dump(mode="python", include={name}, warnings=False)[name]
    except (TypeError, ValueError, KeyError):
        raise DetectionEvaluationError("invalid_evaluation_input") from None
    return _resolved(field_path, kind, value)


def _compare(actual: Scalar, op: DetectionOperator, operands: tuple[Operand, ...]) -> bool:
    if isinstance(actual, datetime):
        actual = actual.astimezone(UTC)
    expected = operands[0]
    match op:
        case DetectionOperator.EQUALS:
            return actual == expected
        case DetectionOperator.NOT_EQUALS:
            return actual != expected
        case DetectionOperator.IN:
            return actual in operands
        case DetectionOperator.NOT_IN:
            return actual not in operands
        case DetectionOperator.CONTAINS:
            return cast(str, expected) in cast(str, actual)
        case DetectionOperator.CONTAINS_ANY:
            return any(cast(str, item) in cast(str, actual) for item in operands)
        case DetectionOperator.STARTS_WITH:
            return cast(str, actual).startswith(cast(str, expected))
        case DetectionOperator.ENDS_WITH:
            return cast(str, actual).endswith(cast(str, expected))
        case DetectionOperator.GREATER_THAN:
            return cast(int, actual) > cast(int, expected)
        case DetectionOperator.GREATER_OR_EQUAL:
            return cast(int, actual) >= cast(int, expected)
        case DetectionOperator.LESS_THAN:
            return cast(int, actual) < cast(int, expected)
        case DetectionOperator.LESS_OR_EQUAL:
            return cast(int, actual) <= cast(int, expected)
        case DetectionOperator.IP_IN_CIDR:
            address = cast(IPv4Address | IPv6Address, actual)
            network = cast(IPv4Network | IPv6Network, expected)
            return address.version == network.version and address in network
    raise DetectionEvaluationError("unsupported_comparison")


def _outcome(value: bool) -> ConditionOutcome:
    return ConditionOutcome.TRUE if value else ConditionOutcome.FALSE


def _evaluate_leaf(event: NormalizedEvent, leaf: LeafCondition, location: str) -> ConditionTrace:
    field = resolve_event_field(event, leaf.field)
    operands = validated_operands(field.field_type, leaf)
    present = field.presence is FieldPresence.PRESENT
    if leaf.op in EXISTENCE_OPERATORS:
        outcome = _outcome(present if leaf.op is DetectionOperator.EXISTS else not present)
    elif not present:
        outcome = ConditionOutcome.UNKNOWN
    else:
        outcome = _outcome(_compare(cast(Scalar, field.value), leaf.op, operands))
    evidence: dict[str, Any] = {}
    if leaf.op not in EXISTENCE_OPERATORS:
        # Copy membership lists so the trace is not an alias of a mutable rule operand.
        evidence["expected"] = list(leaf.value) if isinstance(leaf.value, list) else leaf.value
    if present:
        evidence["actual"] = field.value
    else:
        evidence["absence"] = field.presence.value
    return ConditionTrace(
        location=location, kind="leaf", outcome=outcome, field=leaf.field, op=leaf.op, **evidence
    )


def _evaluate(event: NormalizedEvent, condition: ConditionNode, location: str) -> ConditionTrace:
    if isinstance(condition, LeafCondition):
        return _evaluate_leaf(event, condition, location)
    if isinstance(condition, NotCondition):
        child = _evaluate(event, condition.not_, f"{location}.not")
        outcome = {
            ConditionOutcome.TRUE: ConditionOutcome.FALSE,
            ConditionOutcome.FALSE: ConditionOutcome.TRUE,
            ConditionOutcome.UNKNOWN: ConditionOutcome.UNKNOWN,
        }[child.outcome]
        return ConditionTrace(location=location, kind="not", outcome=outcome, children=[child])
    if isinstance(condition, (AllCondition, AnyCondition)):
        conjunction = isinstance(condition, AllCondition)
        kind: Literal["all", "any"] = "all" if conjunction else "any"
        nodes = condition.all if isinstance(condition, AllCondition) else condition.any
        # Materialize ALL child traces before aggregating their outcomes.
        children = [
            _evaluate(event, node, f"{location}.{kind}[{i}]") for i, node in enumerate(nodes)
        ]
        outcomes = {child.outcome for child in children}
        decisive = ConditionOutcome.FALSE if conjunction else ConditionOutcome.TRUE
        if decisive in outcomes:
            outcome = decisive
        elif ConditionOutcome.UNKNOWN in outcomes:
            outcome = ConditionOutcome.UNKNOWN
        else:
            outcome = ConditionOutcome.TRUE if conjunction else ConditionOutcome.FALSE
        return ConditionTrace(location=location, kind=kind, outcome=outcome, children=children)
    raise DetectionEvaluationError("invalid_condition_node")


def evaluate_condition(event: NormalizedEvent, condition: ConditionNode) -> ConditionTrace:
    """Evaluate one validated tree, with ordered, complete three-valued evidence.

    Invalid fields/types/literals raise controlled errors, never a partial
    trace. This function neither selects rules nor creates matches. Returned
    in-memory evidence contains actual values; callers must apply their safe
    export/redaction policy before publishing it. Nothing is logged here.
    """
    try:
        return _evaluate(event, condition, "$")
    except DetectionEvaluationError:
        raise
    except (TypeError, ValueError, AttributeError, KeyError, OverflowError, RecursionError):
        # Guard unexpected mutated/bypassed model values without disclosing them.
        raise DetectionEvaluationError("invalid_evaluation_input") from None
