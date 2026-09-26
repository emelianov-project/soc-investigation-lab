"""Public rule-loading, condition-evaluation, and stateless engine APIs."""

from .engine import evaluate_event
from .errors import (
    DetectionEngineError,
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
    "DetectionEngineError",
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
    "evaluate_event",
    "load_detection_rules",
    "resolve_event_field",
)
