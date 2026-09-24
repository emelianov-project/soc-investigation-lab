## Testing

### Test layout

`backend/tests/` contains backend unit tests and lightweight backend smoke tests.

`backend/tests/conftest.py` is the shared location for reusable pytest fixtures used by backend tests.

`tests/integration/` contains cross-component event-processing pipeline tests and
quality checks for the synthetic Windows Event XML fixtures.

`tests/fixtures/` contains reusable static fixture data and sample telemetry used by tests.

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

### Run event-processing integration tests

```console
uv run --no-sync pytest tests/integration
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
