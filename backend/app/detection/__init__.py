"""Public rule-loading and single-condition evaluation APIs."""

from .errors import (
    DetectionEvaluationError,
    DetectionRuleFileError,
    DetectionRuleLoadError,
    DuplicateDetectionRuleIdError,
    IncompatibleDetectionConditionError,
    InvalidDetectionFieldError,
)
from .evaluator import (
    FieldPresence,
    FieldType,
    ResolvedField,
    evaluate_condition,
    resolve_event_field,
)
from .loader import load_detection_rules

__all__ = (
    "DetectionEvaluationError",
    "DetectionRuleFileError",
    "DetectionRuleLoadError",
    "DuplicateDetectionRuleIdError",
    "FieldPresence",
    "FieldType",
    "IncompatibleDetectionConditionError",
    "InvalidDetectionFieldError",
    "ResolvedField",
    "evaluate_condition",
    "load_detection_rules",
    "resolve_event_field",
)
