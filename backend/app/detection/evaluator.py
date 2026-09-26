"""Explicit, in-memory evaluation of one condition tree against one event."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Any, Literal, cast

from app.models import (
    AllCondition,
    AnyCondition,
    AuthenticationContext,
    AuthenticationOutcome,
    ConditionNode,
    ConditionOutcome,
    ConditionTrace,
    DetectionOperator,
    DnsContext,
    EventCategory,
    EventContext,
    EventSource,
    FileContext,
    LeafCondition,
    NetworkContext,
    NormalizedEvent,
    NotCondition,
    ProcessContext,
)

from .errors import (
    DetectionEvaluationError,
    IncompatibleDetectionConditionError,
    InvalidDetectionFieldError,
)


class FieldPresence(StrEnum):
    """Missing retained text is distinct from an absent declared field."""

    PRESENT = "present"
    MISSING = "missing"
    ABSENT = "absent"


class FieldType(StrEnum):
    """Semantic types remain known even when optional values are absent."""

    STRING = "string"
    INTEGER = "integer"
    TIMESTAMP = "timestamp"
    IP = "ip"


type Scalar = str | int | datetime | IPv4Address | IPv6Address
type Operand = Scalar | IPv4Network | IPv6Network
type FieldMap = dict[str, tuple[FieldType, Scalar | None]]


@dataclass(frozen=True)
class ResolvedField:
    """A whitelisted field with its declared type and explicit presence state."""

    path: str
    field_type: FieldType
    presence: FieldPresence
    value: Scalar | None


def _context_fields(context: EventContext) -> FieldMap:
    """Only explicit model attributes are accessed, never a user-supplied attribute."""
    match context:
        case AuthenticationContext():
            return {
                "outcome": (FieldType.STRING, context.outcome),
                "user": (FieldType.STRING, context.user),
                "domain": (FieldType.STRING, context.domain),
                "logon_type": (FieldType.INTEGER, context.logon_type),
                "source_ip": (FieldType.IP, context.source_ip),
                "source_port": (FieldType.INTEGER, context.source_port),
                "workstation": (FieldType.STRING, context.workstation),
            }
        case ProcessContext():
            return {
                "image": (FieldType.STRING, context.image),
                "process_id": (FieldType.INTEGER, context.process_id),
                "command_line": (FieldType.STRING, context.command_line),
                "parent_process_id": (FieldType.INTEGER, context.parent_process_id),
                "parent_image": (FieldType.STRING, context.parent_image),
                "user": (FieldType.STRING, context.user),
            }
        case NetworkContext():
            return {
                "source_ip": (FieldType.IP, context.source_ip),
                "source_port": (FieldType.INTEGER, context.source_port),
                "destination_ip": (FieldType.IP, context.destination_ip),
                "destination_port": (FieldType.INTEGER, context.destination_port),
                "protocol": (FieldType.STRING, context.protocol),
                "process_id": (FieldType.INTEGER, context.process_id),
                "process_image": (FieldType.STRING, context.process_image),
            }
        case FileContext():
            return {
                "target_path": (FieldType.STRING, context.target_path),
                "process_id": (FieldType.INTEGER, context.process_id),
                "process_image": (FieldType.STRING, context.process_image),
            }
        case DnsContext():
            return {
                "query_name": (FieldType.STRING, context.query_name),
                "query_status": (FieldType.STRING, context.query_status),
                "query_results": (FieldType.STRING, context.query_results),
                "process_id": (FieldType.INTEGER, context.process_id),
                "process_image": (FieldType.STRING, context.process_image),
            }
    raise DetectionEvaluationError("invalid_context_type")


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
    common: FieldMap = {
        "source": (FieldType.STRING, event.source),
        "provider": (FieldType.STRING, event.provider),
        "event_id": (FieldType.INTEGER, event.event_id),
        "channel": (FieldType.STRING, event.channel),
        "timestamp": (FieldType.TIMESTAMP, event.timestamp),
        "computer": (FieldType.STRING, event.computer),
        "record_id": (FieldType.INTEGER, event.record_id),
        "category": (FieldType.STRING, event.category),
    }
    if field_path in common:
        return _resolved(field_path, *common[field_path])
    parts = field_path.split(".")
    if len(parts) == 2 and parts[0] == "context":
        fields = _context_fields(event.context)
        if parts[1] in fields:
            return _resolved(field_path, *fields[parts[1]])
    if len(parts) == 2 and parts[0] == "source_data":
        name = parts[1]
        if (
            name
            and name.isascii()
            and name[0].isalpha()
            and all(char.isalnum() or char == "_" for char in name)
        ):
            if name not in event.source_data:
                return ResolvedField(field_path, FieldType.STRING, FieldPresence.MISSING, None)
            return _resolved(field_path, FieldType.STRING, event.source_data[name])
    raise InvalidDetectionFieldError(field_path)


_EXISTENCE = {DetectionOperator.EXISTS, DetectionOperator.NOT_EXISTS}
_STRING = {
    DetectionOperator.CONTAINS,
    DetectionOperator.CONTAINS_ANY,
    DetectionOperator.STARTS_WITH,
    DetectionOperator.ENDS_WITH,
}
_INTEGER = {
    DetectionOperator.GREATER_THAN,
    DetectionOperator.GREATER_OR_EQUAL,
    DetectionOperator.LESS_THAN,
    DetectionOperator.LESS_OR_EQUAL,
}
_LIST = {DetectionOperator.IN, DetectionOperator.NOT_IN, DetectionOperator.CONTAINS_ANY}


def _literal(field: ResolvedField, op: DetectionOperator, value: object) -> Scalar:
    """Parse only typed IP/time literals; never coerce strings or integers."""
    if field.field_type is FieldType.INTEGER and type(value) is int:
        return value
    if type(value) is str:
        if field.field_type is FieldType.STRING:
            return value
        try:
            if field.field_type is FieldType.IP:
                return ip_address(value)
            if field.field_type is FieldType.TIMESTAMP:
                timestamp = datetime.fromisoformat(value)
                if timestamp.utcoffset() is not None:
                    return timestamp.astimezone(UTC)
        except (ValueError, OverflowError):
            pass
    raise IncompatibleDetectionConditionError(field.path, op.value, "invalid_literal_type_or_value")


def _operands(field: ResolvedField, leaf: LeafCondition) -> tuple[Operand, ...]:
    """Check compatibility even for absent values, so invalid conditions cannot hide."""
    op = leaf.op
    if not isinstance(op, DetectionOperator):
        raise IncompatibleDetectionConditionError(field.path, "unknown", "unsupported_operator")
    if op in _EXISTENCE:
        if "value" in leaf.model_fields_set:
            raise IncompatibleDetectionConditionError(field.path, op.value, "unexpected_operand")
        return ()
    if (
        (op in _STRING and field.field_type is not FieldType.STRING)
        or (op in _INTEGER and field.field_type is not FieldType.INTEGER)
        or (op is DetectionOperator.IP_IN_CIDR and field.field_type is not FieldType.IP)
    ):
        raise IncompatibleDetectionConditionError(field.path, op.value, "incompatible_field_type")
    if op is DetectionOperator.IP_IN_CIDR:
        if type(leaf.value) is str:
            try:
                return (ip_network(leaf.value),)
            except ValueError:
                pass
        raise IncompatibleDetectionConditionError(field.path, op.value, "invalid_cidr")
    if op in _LIST:
        if not isinstance(leaf.value, list) or not leaf.value:
            raise IncompatibleDetectionConditionError(field.path, op.value, "invalid_operand_list")
        return tuple(_literal(field, op, item) for item in leaf.value)
    return (_literal(field, op, leaf.value),)


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
    operands = _operands(field, leaf)
    present = field.presence is FieldPresence.PRESENT
    if leaf.op in _EXISTENCE:
        outcome = _outcome(present if leaf.op is DetectionOperator.EXISTS else not present)
    elif not present:
        outcome = ConditionOutcome.UNKNOWN
    else:
        outcome = _outcome(_compare(cast(Scalar, field.value), leaf.op, operands))
    evidence: dict[str, Any] = {}
    if leaf.op not in _EXISTENCE:
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
