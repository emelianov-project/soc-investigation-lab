## Development Tooling

Ruff provides Python linting, import sorting, and formatting. mypy performs static type checking, and pre-commit runs the configured quality checks before commits.

### Install development dependencies

```console
uv sync --group dev
```

### Lint

```console
uv run ruff check .
```

### Automatically fix safe lint violations

```console
uv run ruff check --fix .
```

### Format

```console
uv run ruff format .
```

### Check formatting without modifying files

```console
uv run ruff format --check .
```

### Type checking

```console
uv run mypy backend/app
```

Type checking becomes meaningful once Python application source files are introduced.

### Install pre-commit hooks

```console
uv run pre-commit install
```

### Run all pre-commit checks manually

```console
uv run pre-commit run --all-files
```
