"""Offline rule-loading contracts using isolated synthetic YAML libraries."""

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from app.detection import (
    DetectionRuleFileError,
    DetectionRuleLoadError,
    DuplicateDetectionRuleIdError,
    load_detection_rules,
)
from app.detection.loader import _checked_path
from app.models import DetectionRule


def rule_yaml(rule_id: str = "example-process", version: int = 1) -> str:
    return (
        f"id: {rule_id}\nversion: {version}\n"
        "title: Example process rule\n"
        "description: Select a synthetic process event.\n"
        "categories: [process]\n"
        "condition:\n  field: event_id\n  op: equals\n  value: 4688\n"
    )


def write_rule(root: Path, name: str, content: str | None = None) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rule_yaml() if content is None else content, encoding="utf-8")
    return path


@pytest.mark.parametrize("suffix", [".yaml", ".yml"])
def test_loads_one_typed_rule(tmp_path: Path, suffix: str) -> None:
    write_rule(tmp_path, f"example{suffix}")
    rules = load_detection_rules(tmp_path)
    assert isinstance(rules, tuple) and len(rules) == 1
    assert isinstance(rules[0], DetectionRule)
    assert rules[0].id == "example-process"


def test_nested_files_are_ordered_by_relative_posix_path_not_id(tmp_path: Path) -> None:
    write_rule(tmp_path, "z.yml", rule_yaml("first-id"))
    write_rule(tmp_path, "b/deep/a.yaml", rule_yaml("middle-id"))
    write_rule(tmp_path, "a.yaml", rule_yaml("last-id"))
    assert [rule.id for rule in load_detection_rules(tmp_path)] == [
        "last-id",
        "middle-id",
        "first-id",
    ]


def test_enumeration_order_does_not_change_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_rule(tmp_path, "b.yaml", rule_yaml("b-rule"))
    write_rule(tmp_path, "a.yaml", rule_yaml("a-rule"))
    expected = load_detection_rules(tmp_path)
    original = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(reversed(list(original(path)))))
    assert load_detection_rules(tmp_path) == expected


def test_unrelated_extensions_and_empty_directories_are_ignored(tmp_path: Path) -> None:
    for name in (".gitkeep", "bad.txt", "bad.json", "bad.yaml.bak", "bad.YAML"):
        write_rule(tmp_path, name, "not a rule")
    (tmp_path / "nested").mkdir()
    assert load_detection_rules(tmp_path) == ()


def test_empty_library_returns_empty_tuple(tmp_path: Path) -> None:
    assert load_detection_rules(tmp_path) == ()


@pytest.mark.parametrize(
    "content",
    ["", " \n\t", "a scalar", "42", "null", "[]", "- item", "{}", "# comment only\n"],
)
def test_invalid_documents_fail(tmp_path: Path, content: str) -> None:
    write_rule(tmp_path, "nested/invalid.yaml", content)
    with pytest.raises(DetectionRuleFileError) as caught:
        load_detection_rules(tmp_path)
    assert caught.value.path == "nested/invalid.yaml"
    assert caught.value.category in {"invalid_document", "invalid_yaml"}


@pytest.mark.parametrize(
    "content",
    ["condition: [unterminated", rule_yaml() + "---\n" + rule_yaml("second-rule")],
)
def test_malformed_or_multiple_documents_fail(tmp_path: Path, content: str) -> None:
    write_rule(tmp_path, "invalid.yaml", content)
    with pytest.raises(DetectionRuleFileError, match="invalid_yaml"):
        load_detection_rules(tmp_path)


@pytest.mark.parametrize(
    "content",
    [
        rule_yaml().replace("op: equals", "op: execute"),
        rule_yaml("Invalid_ID"),
        rule_yaml().replace("  field: event_id\n  op: equals\n  value: 4688", "  all: []"),
        rule_yaml().replace("version: 1", "version: true"),
        rule_yaml().replace("value: 4688", "value: null"),
        rule_yaml().replace("[process]", "[unsupported]"),
        rule_yaml() + "severity: high\n",
    ],
)
def test_domain_failures_are_reported_with_file_context(tmp_path: Path, content: str) -> None:
    write_rule(tmp_path, "invalid.yaml", content)
    with pytest.raises(DetectionRuleFileError, match="invalid_rule") as caught:
        load_detection_rules(tmp_path)
    assert isinstance(caught.value, DetectionRuleLoadError)
    assert caught.value.path == "invalid.yaml"


@pytest.mark.parametrize("second_version", [1, 2])
def test_duplicate_ids_fail_even_for_different_versions(
    tmp_path: Path, second_version: int
) -> None:
    write_rule(tmp_path, "a.yaml")
    write_rule(tmp_path, "nested/b.yml", rule_yaml(version=second_version))
    with pytest.raises(DuplicateDetectionRuleIdError) as caught:
        load_detection_rules(tmp_path)
    assert caught.value.rule_id == "example-process"
    assert caught.value.first_path == "a.yaml"
    assert caught.value.duplicate_path == "nested/b.yml"
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize(
    "content",
    [
        rule_yaml() + "id: duplicate\n",
        rule_yaml().replace("  op: equals", "  op: equals\n  op: not_equals"),
        rule_yaml() + "'id': duplicate\n",
        "!custom\n" + rule_yaml(),
        "!!python/object/apply:builtins.int ['42']",
        "!!python/tuple [1, 2]",
        "&shared\n" + rule_yaml(),
        "id: *undefined\n",
        rule_yaml().replace(
            "title: Example process rule", "title: &name Example\ndescription: *name"
        ),
        "<<: {id: example-process}\n" + rule_yaml(),
        rule_yaml() + "'<<': {}\n",
        "? [complex, key]\n: value\n",
        "1: value\n",
    ],
)
def test_unsafe_yaml_is_rejected_before_construction(tmp_path: Path, content: str) -> None:
    write_rule(tmp_path, "unsafe.yaml", content)
    with pytest.raises(DetectionRuleFileError, match="unsafe_yaml"):
        load_detection_rules(tmp_path)


def test_invalid_utf8_fails_without_replacement(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_bytes(b"\xff\xfe\x80")
    with pytest.raises(DetectionRuleFileError, match="invalid_utf8"):
        load_detection_rules(tmp_path)


def test_one_bad_file_prevents_any_partial_return(tmp_path: Path) -> None:
    write_rule(tmp_path, "a-valid.yaml")
    write_rule(tmp_path, "z-invalid.yaml", "[]")
    with pytest.raises(DetectionRuleLoadError):
        load_detection_rules(tmp_path)


def test_errors_hide_document_and_absolute_path(tmp_path: Path) -> None:
    write_rule(tmp_path, "nested/bad.yaml", "title: synthetic-private-marker\ncondition: [")
    with pytest.raises(DetectionRuleFileError) as caught:
        load_detection_rules(tmp_path)
    assert str(caught.value) == "'nested/bad.yaml': invalid_yaml"
    assert "synthetic-private-marker" not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)
    assert caught.value.__suppress_context__


def test_read_error_is_controlled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_rule(tmp_path, "example.yaml")

    def fail_read(path: Path, **kwargs: object) -> str:
        raise PermissionError("private filesystem details")

    monkeypatch.setattr(Path, "read_text", fail_read)
    with pytest.raises(DetectionRuleFileError, match="read_error") as caught:
        load_detection_rules(tmp_path)
    assert "private filesystem details" not in str(caught.value)


def test_missing_or_nondirectory_root_is_controlled(tmp_path: Path) -> None:
    with pytest.raises(DetectionRuleFileError, match="invalid_root"):
        load_detection_rules(tmp_path / "missing")
    file = write_rule(tmp_path, "file.yaml")
    with pytest.raises(DetectionRuleFileError, match="invalid_root"):
        load_detection_rules(file)


def test_absolute_root_is_independent_of_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "rules"
    write_rule(root, "example.yaml")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert len(load_detection_rules(root)) == 1
    with pytest.raises(DetectionRuleFileError, match="absolute_root_required"):
        load_detection_rules(Path("rules"))


def test_outside_file_and_parent_escape_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    outside = write_rule(tmp_path, "outside.yaml")
    assert load_detection_rules(root) == ()
    for candidate in (outside, root / ".." / "outside.yaml"):
        with pytest.raises(DetectionRuleFileError, match="unsafe_path"):
            _checked_path(root, candidate)


@pytest.mark.parametrize("directory", [False, True])
def test_real_escaping_symlinks_are_rejected(tmp_path: Path, directory: bool) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    file = write_rule(outside, "example.yaml")
    link = root / ("linked-directory" if directory else "linked.yaml")
    try:
        link.symlink_to(outside if directory else file, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("OS does not permit symlinks; deterministic link tests still run")
    with pytest.raises(DetectionRuleFileError, match="unsafe_path"):
        load_detection_rules(root)


@pytest.mark.parametrize("directory", [False, True])
def test_link_rejection_is_testable_without_symlink_privileges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    directory: bool,
) -> None:
    candidate = tmp_path / ("linked-directory" if directory else "linked.yaml")
    if directory:
        candidate.mkdir()
    else:
        write_rule(tmp_path, candidate.name)
    original = Path.lstat

    def link_metadata(path: Path) -> os.stat_result:
        if path == candidate:
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return original(path)

    monkeypatch.setattr(Path, "lstat", link_metadata)
    with pytest.raises(DetectionRuleFileError, match="unsafe_path"):
        load_detection_rules(tmp_path)


def test_resolved_escape_is_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "rules"
    candidate = write_rule(root, "example.yaml")
    outside = write_rule(tmp_path, "outside.yaml")
    original = Path.resolve

    def escaping_resolve(path: Path, strict: bool = False) -> Path:
        return outside if path == candidate else original(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", escaping_resolve)
    with pytest.raises(DetectionRuleFileError, match="unsafe_path"):
        load_detection_rules(root)


def test_expression_like_text_remains_inert_data(tmp_path: Path) -> None:
    content = rule_yaml().replace("Example process rule", "example_callback()")
    write_rule(tmp_path, "example.yaml", content)
    assert load_detection_rules(tmp_path)[0].title == "example_callback()"


def test_windows_directory_reparse_points_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "junction"
    candidate.mkdir()
    original = Path.lstat

    def reparse_metadata(path: Path) -> os.stat_result:
        if path == candidate:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFDIR,
                    st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                ),
            )
        return original(path)

    monkeypatch.setattr(Path, "lstat", reparse_metadata)
    with pytest.raises(DetectionRuleFileError, match="unsafe_path"):
        load_detection_rules(tmp_path)


def test_nonregular_yaml_file_is_rejected_without_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = write_rule(tmp_path, "pipe.yaml")
    original = Path.lstat

    def pipe_metadata(path: Path) -> os.stat_result:
        if path == candidate:
            return cast(
                os.stat_result,
                SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_file_attributes=0),
            )
        return original(path)

    monkeypatch.setattr(Path, "lstat", pipe_metadata)
    with pytest.raises(DetectionRuleFileError, match="not_regular_file"):
        load_detection_rules(tmp_path)


def test_discovery_permission_error_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_iterdir(path: Path) -> None:
        raise PermissionError("private filesystem details")

    monkeypatch.setattr(Path, "iterdir", fail_iterdir)
    with pytest.raises(DetectionRuleFileError, match="read_error") as caught:
        load_detection_rules(tmp_path)
    assert caught.value.path == "."


def test_nested_condition_and_source_scope_validate_through_domain_model(tmp_path: Path) -> None:
    content = rule_yaml().split("condition:")[0] + (
        "sources: [windows_security]\ncondition:\n  all:\n"
        "    - field: event_id\n      op: equals\n      value: 4688\n"
        "    - not:\n        field: source_data.ExampleField\n        op: exists\n"
    )
    write_rule(tmp_path, "nested/example.yaml", content)
    assert load_detection_rules(tmp_path)[0] == DetectionRule.model_validate(
        {
            "id": "example-process",
            "version": 1,
            "title": "Example process rule",
            "description": "Select a synthetic process event.",
            "categories": ["process"],
            "sources": ["windows_security"],
            "condition": {
                "all": [
                    {"field": "event_id", "op": "equals", "value": 4688},
                    {"not": {"field": "source_data.ExampleField", "op": "exists"}},
                ]
            },
        }
    )
