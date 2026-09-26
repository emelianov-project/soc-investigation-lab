"""Controlled failures at the detection-rule loading boundary."""


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
