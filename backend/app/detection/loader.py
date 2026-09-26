"""Deterministic, data-only YAML loading inside an explicit rule-library root."""

import stat
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from yaml import SafeLoader, YAMLError, parse
from yaml.events import AliasEvent, CollectionStartEvent, ScalarEvent
from yaml.nodes import MappingNode, ScalarNode

from app.models import DetectionRule

from .errors import DetectionRuleFileError, DuplicateDetectionRuleIdError


class _UnsafeYamlError(ValueError):
    """Internal marker; YAML content is never included in public errors."""


class _RuleSafeLoader(SafeLoader):
    """SafeLoader with a closed rule-data syntax and duplicate-key checks."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        keys: set[str] = set()
        for key, _ in node.value:
            if (
                not isinstance(key, ScalarNode)
                or key.tag != "tag:yaml.org,2002:str"
                or key.value == "<<"
                or key.value in keys
            ):
                raise _UnsafeYamlError
            keys.add(key.value)
        return super().construct_mapping(node, deep=deep)


def _relative_path(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "<outside-root>"
    if ".." in relative.parts:
        return "<outside-root>"
    return relative.as_posix()


def _checked_path(root: Path, path: Path) -> Path:
    """Reject links and escapes before accessing a discovered path.

    All links are rejected, including in-root symlinks and Windows reparse
    points. This prevents directory cycles as well as out-of-root traversal.
    """
    relative = _relative_path(root, path)
    if relative == "<outside-root>":
        raise DetectionRuleFileError(relative, "unsafe_path")
    try:
        current = root
        for part in ("", *path.relative_to(root).parts):
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or (
                getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise DetectionRuleFileError(relative, "unsafe_path")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise DetectionRuleFileError(relative, "unsafe_path")
        return resolved
    except (OSError, RuntimeError):
        raise DetectionRuleFileError(relative, "path_error") from None


def _discover(root: Path) -> list[Path]:
    files: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        checked = _checked_path(root, directory)
        try:
            entries = sorted(checked.iterdir(), key=lambda path: path.name)
        except OSError:
            raise DetectionRuleFileError(_relative_path(root, directory), "read_error") from None
        directories: list[Path] = []
        for entry in entries:
            checked = _checked_path(root, entry)
            try:
                mode = checked.lstat().st_mode
            except OSError:
                raise DetectionRuleFileError(_relative_path(root, entry), "path_error") from None
            if stat.S_ISDIR(mode):
                directories.append(entry)
            elif entry.suffix in {".yaml", ".yml"}:
                if not stat.S_ISREG(mode):
                    raise DetectionRuleFileError(_relative_path(root, entry), "not_regular_file")
                files.append(entry)
        pending.extend(reversed(directories))
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _load_file(root: Path, path: Path) -> DetectionRule:
    relative = _relative_path(root, path)
    checked = _checked_path(root, path)
    try:
        if not stat.S_ISREG(checked.lstat().st_mode):
            raise DetectionRuleFileError(relative, "not_regular_file")
        content = checked.read_text(encoding="utf-8")
    except UnicodeError:
        raise DetectionRuleFileError(relative, "invalid_utf8") from None
    except OSError:
        raise DetectionRuleFileError(relative, "read_error") from None
    try:
        # Parse events without constructing values first. Reject graph references
        # and explicit tags before SafeLoader can construct any document objects.
        for event in parse(content, Loader=SafeLoader):
            if isinstance(event, AliasEvent):
                raise _UnsafeYamlError
            if isinstance(event, (ScalarEvent, CollectionStartEvent)) and (
                event.anchor is not None or event.tag is not None
            ):
                raise _UnsafeYamlError
        loader = _RuleSafeLoader(content)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
    except _UnsafeYamlError:
        raise DetectionRuleFileError(relative, "unsafe_yaml") from None
    except (YAMLError, ValueError, RecursionError):
        raise DetectionRuleFileError(relative, "invalid_yaml") from None
    if not isinstance(document, dict) or not document:
        raise DetectionRuleFileError(relative, "invalid_document")
    try:
        return DetectionRule.model_validate(document)
    except ValidationError:
        raise DetectionRuleFileError(relative, "invalid_rule") from None


def load_detection_rules(rule_root: Path) -> tuple[DetectionRule, ...]:
    """Load a complete library, sorted by root-relative POSIX path.

    Supply an absolute directory so behavior does not depend on the working
    directory. Its resolved location is the trust boundary. Only regular
    .yaml/.yml files are loaded; any link below the root is rejected. Keep the
    library unchanged during loading. Empty libraries return an empty tuple.
    No partial result is returned on any file, YAML, model, or duplicate error.
    """
    if not rule_root.is_absolute():
        raise DetectionRuleFileError(".", "absolute_root_required")
    try:
        root = rule_root.resolve(strict=True)
        if not root.is_dir():
            raise DetectionRuleFileError(".", "invalid_root")
    except (OSError, RuntimeError):
        raise DetectionRuleFileError(".", "invalid_root") from None
    rules: list[DetectionRule] = []
    ids: dict[str, str] = {}
    for path in _discover(root):
        rule = _load_file(root, path)
        relative = path.relative_to(root).as_posix()
        if rule.id in ids:
            raise DuplicateDetectionRuleIdError(rule.id, ids[rule.id], relative)
        ids[rule.id] = relative
        rules.append(rule)
    return tuple(rules)
