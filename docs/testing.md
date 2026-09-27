## Testing

### Test layout

`backend/tests/` contains backend unit tests and lightweight backend smoke tests.

`backend/tests/conftest.py` is the shared location for reusable pytest fixtures used by backend tests.

`tests/integration/` contains cross-component event-processing and Detection Engine
pipeline tests, plus quality checks for the synthetic Windows Event XML fixtures.

`tests/fixtures/` contains reusable static fixture data and sample telemetry used by tests.

### Detection Engine coverage

The implementation for v0.3.0 is complete on main; release is pending. Tests
exercise the boundary through `DetectionMatch`, not Alert or investigation
behavior:

| Layer | Coverage / location |
| --- | --- |
| Domain contracts | [`test_detection.py`](../backend/tests/models/test_detection.py): rule/condition/trace/match shapes, closed operators, bounds, source scope, and safe evidence. |
| Loader and shared semantics | [`test_loader.py`](../backend/tests/detection/test_loader.py): temporary synthetic YAML trees, deterministic path order, path/link containment, UTF-8 and safe YAML rejection, whole-load failure, duplicates, every operator/type pairing, typed operands, nested leaves, every target category, and source-data scope. |
| Evaluator | [`test_evaluator.py`](../backend/tests/detection/test_evaluator.py): all fields and 15 operators, strict types, IP/CIDR/time semantics, missing/absent states, full three-valued truth tables, ordered complete traces, and defensive runtime failures for direct/bypassed inputs. |
| Engine | [`test_engine.py`](../backend/tests/detection/test_engine.py): category/source targeting before evaluation, rule-ID order, TRUE-only matches, duplicates, no partial results, and repeatability without input mutation. |
| Committed library | [`test_rule_library.py`](../backend/tests/detection/test_rule_library.py): exactly six real rules, synthetic positive/negative cases, case-sensitive markers, optional data, identity, and explanation. |
| XML-to-match integration | [`test_detection_pipeline.py`](../tests/integration/test_detection_pipeline.py): real normalization and rule loading through match/trace output, safe XML variations, negative cases, absent optional fields, targeting, multiple-match ordering, and loading/semantic failure paths. |

Unknown fields and incompatible operator/type combinations are now rejected
during loading; evaluator defense remains for invalid direct Python objects.
No invalid rule is skipped and no partial library or match tuple is returned.
Loader tests use `tmp_path`, not new production rules. Direct symlink tests may
skip on Windows without symlink privileges; deterministic containment and
Windows-reparse-point simulations still run.

All inputs are synthetic/public-safe and checks are offline and deterministic.
Tests do not execute command-line text, contact external services, or require a
database. See [Rule Authoring](detections/rule-authoring.md) for safe examples and
[Detection Engine Architecture](architecture/detection-engine.md) for the contract.

### Install test dependencies

```console
uv sync --locked --group dev --group test
```

Test-specific dependencies belong in the `test` dependency group.

### Run the complete test suite

```console
uv run --no-sync pytest
```

### Run backend tests only

```console
uv run --no-sync pytest backend/tests
```

### Run event-processing and detection integration tests

```console
uv run --no-sync pytest tests/integration
```

### Run focused detection tests

```console
uv run --no-sync pytest backend/tests/detection
uv run --no-sync pytest tests/integration/test_detection_pipeline.py
```

### Run a specific test file

```console
uv run --no-sync pytest backend/tests/test_smoke.py
```

### Run the repository quality gate

After a locked sync, run `uv lock --check`, `git diff --check`, Ruff lint and
format checks, strict mypy on both `backend/tests` and `tests/integration`, the
complete pytest suite, and `uv run --no-sync pre-commit run --all-files`.
The pull-request `Backend quality` check is a separate required CI gate.
