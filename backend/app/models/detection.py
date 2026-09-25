"""Closed, data-only contracts for v0.3 detection rules and match evidence.

This module defines the shapes of rules and explanations. It does not load
rules, resolve event fields, or evaluate conditions.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from .normalized_event import EventCategory, EventSource, NormalizedEvent


class DetectionOperator(StrEnum):
    """The complete initial set of declarative comparison operators."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    CONTAINS_ANY = "contains_any"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    GREATER_THAN = "greater_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_THAN = "less_than"
    LESS_OR_EQUAL = "less_or_equal"
    IP_IN_CIDR = "ip_in_cidr"


class ConditionOutcome(StrEnum):
    """Three-valued outcome of a condition, without evaluation semantics."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


_COMMON_FIELDS = frozenset(
    {"source", "provider", "event_id", "channel", "timestamp", "computer", "record_id", "category"}
)
_SEGMENT = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_RULE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_STRING_OPERATORS = frozenset(
    {
        DetectionOperator.CONTAINS,
        DetectionOperator.STARTS_WITH,
        DetectionOperator.ENDS_WITH,
        DetectionOperator.IP_IN_CIDR,
    }
)
_INTEGER_OPERATORS = frozenset(
    {
        DetectionOperator.GREATER_THAN,
        DetectionOperator.GREATER_OR_EQUAL,
        DetectionOperator.LESS_THAN,
        DetectionOperator.LESS_OR_EQUAL,
    }
)
_LIST_OPERATORS = frozenset(
    {DetectionOperator.CONTAINS_ANY, DetectionOperator.IN, DetectionOperator.NOT_IN}
)


class _DetectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _valid_path(path: str) -> bool:
    if path in _COMMON_FIELDS:
        return True
    parts = path.split(".")
    return (
        len(parts) == 2
        and parts[0] in {"context", "source_data"}
        and bool(_SEGMENT.fullmatch(parts[1]))
    )


def _valid_operand(operator: DetectionOperator, value: object) -> bool:
    if operator in _LIST_OPERATORS:
        if not isinstance(value, list) or not value:
            return False
        if operator is DetectionOperator.CONTAINS_ANY:
            return all(type(item) is str for item in value)
        return all(type(item) is type(value[0]) for item in value) and type(value[0]) in {
            str,
            int,
        }
    if operator in _INTEGER_OPERATORS:
        return type(value) is int
    if operator in _STRING_OPERATORS:
        return type(value) is str
    return type(value) in {str, int}


def _safe_actual(value: object) -> bool:
    """Keep explanation values within the normalized event's scalar domain."""
    if type(value) in {str, int, bool, IPv4Address, IPv6Address} or isinstance(value, StrEnum):
        return True
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
    )


class LeafCondition(_DetectionModel):
    """One syntactically valid field comparison; type compatibility is later work."""

    field: StrictStr
    op: DetectionOperator
    value: Any = None

    @model_validator(mode="after")
    def validate_leaf(self) -> Self:
        if not _valid_path(self.field):
            raise ValueError("invalid detection field path")
        has_value = "value" in self.model_fields_set
        if self.op in {DetectionOperator.EXISTS, DetectionOperator.NOT_EXISTS}:
            if has_value:
                raise ValueError("existence operators must omit value")
        elif not has_value or not _valid_operand(self.op, self.value):
            raise ValueError("invalid or missing operand for detection operator")
        return self


class AllCondition(_DetectionModel):
    """Ordered conjunction of one or more conditions."""

    all: Annotated[list[ConditionNode], Field(min_length=1, strict=True)]


class AnyCondition(_DetectionModel):
    """Ordered disjunction of one or more conditions."""

    any: Annotated[list[ConditionNode], Field(min_length=1, strict=True)]


class NotCondition(_DetectionModel):
    """Negation with exactly one child."""

    not_: ConditionNode = Field(alias="not")


ConditionNode = LeafCondition | AllCondition | AnyCondition | NotCondition
AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()


def _measure(node: ConditionNode) -> tuple[int, int]:
    """Return depth and leaf count for a fully validated condition tree."""
    if isinstance(node, LeafCondition):
        return 1, 1
    children = (
        node.all
        if isinstance(node, AllCondition)
        else node.any
        if isinstance(node, AnyCondition)
        else [node.not_]
    )
    child_sizes = [_measure(child) for child in children]
    return 1 + max(depth for depth, _ in child_sizes), sum(leaves for _, leaves in child_sizes)


def _uses_source_data(node: ConditionNode) -> bool:
    if isinstance(node, LeafCondition):
        return node.field.startswith("source_data.")
    children = (
        node.all
        if isinstance(node, AllCondition)
        else node.any
        if isinstance(node, AnyCondition)
        else [node.not_]
    )
    return any(_uses_source_data(child) for child in children)


class DetectionRule(_DetectionModel):
    """A bounded declarative rule independent of loading and evaluation."""

    id: StrictStr
    version: Annotated[StrictInt, Field(gt=0)]
    title: StrictStr
    description: StrictStr
    categories: Annotated[list[EventCategory], Field(min_length=1, strict=True)]
    sources: Annotated[list[EventSource], Field(min_length=1, strict=True)] | None = None
    condition: ConditionNode

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        if not _RULE_ID.fullmatch(self.id):
            raise ValueError("rule id must be a lowercase slug")
        if not self.title.strip() or not self.description.strip():
            raise ValueError("rule title and description must be non-empty")
        if len(set(self.categories)) != len(self.categories):
            raise ValueError("rule categories must be unique")
        if "sources" in self.model_fields_set and self.sources is None:
            raise ValueError("sources must be omitted or non-empty")
        if self.sources is not None and len(set(self.sources)) != len(self.sources):
            raise ValueError("rule sources must be unique")
        depth, leaves = _measure(self.condition)
        if depth > 8 or leaves > 64:
            raise ValueError("condition exceeds maximum depth or leaf count")
        if _uses_source_data(self.condition) and self.sources is None:
            raise ValueError("source_data conditions require sources")
        return self


class ConditionTrace(_DetectionModel):
    """Ordered, safe-to-render evidence for one condition-tree node."""

    location: StrictStr
    kind: Literal["leaf", "all", "any", "not"]
    outcome: ConditionOutcome
    children: list[ConditionTrace] = Field(default_factory=list, strict=True)
    field: StrictStr | None = None
    op: DetectionOperator | None = None
    expected: Any = None
    actual: Any = None
    absence: Literal["missing", "absent"] | None = None
    redacted: StrictBool = False
    redaction_marker: StrictStr | None = None

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        if not re.fullmatch(r"\$(?:\.(?:all|any)\[\d+\]|\.not)*", self.location):
            raise ValueError("invalid trace location")
        if self.kind == "leaf":
            if (
                self.children
                or self.field is None
                or self.op is None
                or not _valid_path(self.field)
            ):
                raise ValueError("leaf trace requires field and operator, without children")
            if self.op in {DetectionOperator.EXISTS, DetectionOperator.NOT_EXISTS}:
                if "expected" in self.model_fields_set:
                    raise ValueError("existence trace must omit expected value")
            elif "expected" not in self.model_fields_set or not _valid_operand(
                self.op, self.expected
            ):
                raise ValueError("leaf trace requires a valid expected operand")
        elif (
            self.field is not None
            or self.op is not None
            or "expected" in self.model_fields_set
            or "actual" in self.model_fields_set
            or self.absence is not None
        ):
            raise ValueError("logical trace cannot contain leaf evidence")
        elif (self.kind == "not" and len(self.children) != 1) or (
            self.kind in {"all", "any"} and not self.children
        ):
            raise ValueError("logical trace has invalid child count")
        if self.kind == "not" and self.children[0].location != f"{self.location}.not":
            raise ValueError("negated child has an inconsistent trace location")
        if self.kind in {"all", "any"} and any(
            child.location != f"{self.location}.{self.kind}[{index}]"
            for index, child in enumerate(self.children)
        ):
            raise ValueError("child has an inconsistent trace location")
        if self.redacted != (self.redaction_marker is not None):
            raise ValueError("redaction requires a marker and vice versa")
        if self.redaction_marker is not None and not self.redaction_marker:
            raise ValueError("redaction marker must be non-empty")
        if self.kind != "leaf" and self.redacted:
            raise ValueError("logical trace cannot be redacted")
        if self.redacted and "actual" in self.model_fields_set:
            raise ValueError("redacted trace must omit actual value")
        if self.absence is not None and "actual" in self.model_fields_set:
            raise ValueError("absent or missing trace must omit actual value")
        if "actual" in self.model_fields_set and not _safe_actual(self.actual):
            raise ValueError("trace actual must be a normalized scalar value")
        if self.kind == "leaf" and not (
            "actual" in self.model_fields_set or self.absence is not None or self.redacted
        ):
            raise ValueError("leaf trace requires actual, absence reason, or redaction")
        return self


ConditionTrace.model_rebuild()


class DetectionMatch(_DetectionModel):
    """Evidence of one successful rule/event match, never an Alert."""

    rule_id: StrictStr
    rule_version: Annotated[StrictInt, Field(gt=0)]
    rule_title: StrictStr
    event: NormalizedEvent
    root_outcome: ConditionOutcome
    trace: ConditionTrace

    @model_validator(mode="after")
    def validate_match(self) -> Self:
        if not _RULE_ID.fullmatch(self.rule_id) or not self.rule_title.strip():
            raise ValueError("match requires a valid rule identity")
        if (
            self.root_outcome is not ConditionOutcome.TRUE
            or self.trace.outcome is not ConditionOutcome.TRUE
        ):
            raise ValueError("a detection match requires a true root outcome")
        if self.trace.location != "$":
            raise ValueError("match trace must start at the root")
        return self
