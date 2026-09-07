## Testing

### Test layout

`backend/tests/` contains backend unit tests and lightweight backend smoke tests.

`backend/tests/conftest.py` is the shared location for reusable pytest fixtures used by backend tests.

`tests/integration/` contains future cross-component integration tests.

`tests/fixtures/` contains reusable static fixture data and sample telemetry used by tests.

### Install test dependencies

```console
uv sync --group test
```

Test-specific dependencies belong in the `test` dependency group.

### Run the complete test suite

```console
uv run --group test pytest
```

### Run backend tests only

```console
uv run --group test pytest backend/tests
```

### Run a specific test file

```console
uv run --group test pytest backend/tests/test_smoke.py
```
