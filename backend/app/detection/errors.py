"""Controlled failures at the loading, evaluation, and engine boundaries."""


class DetectionRuleLoadError(ValueError):
    """The complete rule library could not be loaded safely."""


class DetectionRuleFileError(DetectionRuleLoadError):
    """A path, file, YAML document, or rule failed validation."""

    def __init__(self, path: str, category: str) -> None:
        self.path = path
        self.category = category
        super().__init__(f"{path!r}: {category}")


class DuplicateDetectionRuleIdError(DetectionRuleLoadError):
    """Two files declare the same rule identity, irrespective of version."""

    def __init__(self, rule_id: str, first_path: str, duplicate_path: str) -> None:
        self.rule_id = rule_id
        self.first_path = first_path
        self.duplicate_path = duplicate_path
        super().__init__(f"duplicate rule id {rule_id!r}: {first_path!r} and {duplicate_path!r}")


class DetectionEvaluationError(ValueError):
    """A condition could not be evaluated; no partial trace is returned."""


class DetectionEngineError(DetectionEvaluationError):
    """Invalid engine inputs or match construction, without event/operand contents."""

    def __init__(self, reason: str, rule_id: str | None = None) -> None:
        self.reason = reason
        self.rule_id = rule_id
        context = f"rule {rule_id!r}: " if rule_id is not None else ""
        super().__init__(f"{context}{reason}")


class InvalidDetectionFieldError(DetectionEvaluationError):
    """A field is not in the explicit event/context contract."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"{field!r}: invalid_field")


class IncompatibleDetectionConditionError(DetectionEvaluationError):
    """A field, operator, or literal has incompatible semantics."""

    def __init__(self, field: str, operator: str, reason: str) -> None:
        self.field = field
        self.operator = operator
        self.reason = reason
        super().__init__(f"{field!r} ({operator}): {reason}")
