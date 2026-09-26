"""Shared field and operand semantics, independent of YAML, files, and event values."""

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from app.models import (
    AllCondition,
    AnyCondition,
    AuthenticationContext,
    ConditionNode,
    DetectionOperator,
    DetectionRule,
    DnsContext,
    EventCategory,
    EventContext,
    FileContext,
    LeafCondition,
    NetworkContext,
    NotCondition,
    ProcessContext,
)

from .errors import (
    DetectionEvaluationError,
    IncompatibleDetectionConditionError,
    InvalidDetectionFieldError,
)


class FieldType(StrEnum):
    """Semantic types remain known even when optional values are absent."""

    STRING = "string"
    INTEGER = "integer"
    TIMESTAMP = "timestamp"
    IP = "ip"


type Scalar = str | int | datetime | IPv4Address | IPv6Address
type Operand = Scalar | IPv4Network | IPv6Network

_COMMON_FIELDS = {
    "source": FieldType.STRING,
    "provider": FieldType.STRING,
    "event_id": FieldType.INTEGER,
    "channel": FieldType.STRING,
    "timestamp": FieldType.TIMESTAMP,
    "computer": FieldType.STRING,
    "record_id": FieldType.INTEGER,
    "category": FieldType.STRING,
}
_CONTEXT_FIELDS = {
    EventCategory.AUTHENTICATION: {
        "outcome": FieldType.STRING,
        "user": FieldType.STRING,
        "domain": FieldType.STRING,
        "logon_type": FieldType.INTEGER,
        "source_ip": FieldType.IP,
        "source_port": FieldType.INTEGER,
        "workstation": FieldType.STRING,
    },
    EventCategory.PROCESS: {
        "image": FieldType.STRING,
        "process_id": FieldType.INTEGER,
        "command_line": FieldType.STRING,
        "parent_process_id": FieldType.INTEGER,
        "parent_image": FieldType.STRING,
        "user": FieldType.STRING,
    },
    EventCategory.NETWORK: {
        "source_ip": FieldType.IP,
        "source_port": FieldType.INTEGER,
        "destination_ip": FieldType.IP,
        "destination_port": FieldType.INTEGER,
        "protocol": FieldType.STRING,
        "process_id": FieldType.INTEGER,
        "process_image": FieldType.STRING,
    },
    EventCategory.FILE: {
        "target_path": FieldType.STRING,
        "process_id": FieldType.INTEGER,
        "process_image": FieldType.STRING,
    },
    EventCategory.DNS: {
        "query_name": FieldType.STRING,
        "query_status": FieldType.STRING,
        "query_results": FieldType.STRING,
        "process_id": FieldType.INTEGER,
        "process_image": FieldType.STRING,
    },
}
_CONTEXT_TYPES: dict[EventCategory, type[EventContext]] = {
    EventCategory.AUTHENTICATION: AuthenticationContext,
    EventCategory.PROCESS: ProcessContext,
    EventCategory.NETWORK: NetworkContext,
    EventCategory.FILE: FileContext,
    EventCategory.DNS: DnsContext,
}


def context_type(category: EventCategory) -> type[EventContext]:
    """The actual context must agree with the category used for semantic checks."""
    return _CONTEXT_TYPES[category]


def field_type(field: str, category: EventCategory) -> FieldType:
    """Resolve a closed data path against one category, without an event instance."""
    if field in _COMMON_FIELDS:
        return _COMMON_FIELDS[field]
    parts = field.split(".")
    if len(parts) == 2:
        prefix, name = parts
        if prefix == "context" and name in _CONTEXT_FIELDS[category]:
            return _CONTEXT_FIELDS[category][name]
        if (
            prefix == "source_data"
            and name
            and name.isascii()
            and name[0].isalpha()
            and all(char.isalnum() or char == "_" for char in name)
        ):
            return FieldType.STRING
    raise InvalidDetectionFieldError(field)


EXISTENCE_OPERATORS = frozenset({DetectionOperator.EXISTS, DetectionOperator.NOT_EXISTS})
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


def _literal(field: str, kind: FieldType, op: DetectionOperator, value: object) -> Scalar:
    """Parse only typed IP/time literals; never coerce strings or integers."""
    if kind is FieldType.INTEGER and type(value) is int:
        return value
    if type(value) is str:
        if kind is FieldType.STRING:
            return value
        try:
            if kind is FieldType.IP:
                return ip_address(value)
            if kind is FieldType.TIMESTAMP:
                timestamp = datetime.fromisoformat(value)
                if timestamp.utcoffset() is not None:
                    return timestamp.astimezone(UTC)
        except (ValueError, OverflowError):
            pass
    raise IncompatibleDetectionConditionError(field, op.value, "invalid_literal_type_or_value")


def validated_operands(kind: FieldType, leaf: LeafCondition) -> tuple[Operand, ...]:
    """Validate compatibility and every operand, even without an actual field value."""
    op = leaf.op
    if not isinstance(op, DetectionOperator):
        raise IncompatibleDetectionConditionError(leaf.field, "unknown", "unsupported_operator")
    if op in EXISTENCE_OPERATORS:
        if "value" in leaf.model_fields_set:
            raise IncompatibleDetectionConditionError(leaf.field, op.value, "unexpected_operand")
        return ()
    if (
        (op in _STRING and kind is not FieldType.STRING)
        or (op in _INTEGER and kind is not FieldType.INTEGER)
        or (op is DetectionOperator.IP_IN_CIDR and kind is not FieldType.IP)
    ):
        raise IncompatibleDetectionConditionError(leaf.field, op.value, "incompatible_field_type")
    if op is DetectionOperator.IP_IN_CIDR:
        if type(leaf.value) is str:
            try:
                return (ip_network(leaf.value),)
            except ValueError:
                pass
        raise IncompatibleDetectionConditionError(leaf.field, op.value, "invalid_cidr")
    if op in _LIST:
        if not isinstance(leaf.value, list) or not leaf.value:
            raise IncompatibleDetectionConditionError(leaf.field, op.value, "invalid_operand_list")
        return tuple(_literal(leaf.field, kind, op, item) for item in leaf.value)
    return (_literal(leaf.field, kind, op, leaf.value),)


def _validate_node(node: ConditionNode, rule: DetectionRule) -> None:
    if isinstance(node, LeafCondition):
        if node.field.startswith("source_data.") and not rule.sources:
            raise IncompatibleDetectionConditionError(node.field, node.op.value, "sources_required")
        kinds = [field_type(node.field, category) for category in rule.categories]
        if len(set(kinds)) != 1:
            raise IncompatibleDetectionConditionError(
                node.field, node.op.value, "incompatible_category_types"
            )
        validated_operands(kinds[0], node)
        return
    if isinstance(node, AllCondition):
        children = node.all
    elif isinstance(node, AnyCondition):
        children = node.any
    elif isinstance(node, NotCondition):
        children = [node.not_]
    else:
        raise DetectionEvaluationError("invalid_condition_node")
    for child in children:
        _validate_node(child, rule)


def validate_detection_rule_semantics(rule: DetectionRule) -> None:
    """Check a structurally validated rule for every target category, without mutation.

    Reuses controlled field/condition errors with the evaluator. The loader
    translates these into its file-aware invalid_rule boundary. No event,
    YAML, filesystem, or evaluation result is needed for semantic validation.
    """
    _validate_node(rule.condition, rule)
