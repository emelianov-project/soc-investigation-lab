# Local Development Configuration

## Purpose

This document defines foundation-level conventions for safe, consistent local configuration in SOC Investigation Lab. It does not define production deployment configuration.

## Environment Files

`.env.example` is the public, versioned template for local configuration. Copy it to `.env` when developer-local configuration is needed. The local `.env` file must never be committed.

The v0.1.0 foundation has no mandatory application-specific environment variables. Future Issues may introduce real configuration requirements; when they do, document only safe placeholders or defaults in `.env.example`.

## Environment-Specific Files

Local variants such as `.env.local`, `.env.development`, and `.env.test` are examples of developer-local environment files. The `.env.*` ignore rule keeps such variants untracked; it does not require every future environment to use these names.

`.env.example` is intentionally exempted from that rule so the safe public template remains versioned.

## Safe Configuration Rules

Never commit passwords, API keys, tokens, private keys, real production values, employer or client configuration, corporate infrastructure identifiers, personal data, or credential-bearing connection details.

Tracked examples must use only fictional, reserved, or otherwise safe placeholder values. Local configuration does not override the repository's [Security and Safe Data Handling Policy](../SECURITY.md).

## Editor Configuration

`.editorconfig` standardizes basic editor behavior across environments:

- UTF-8 text encoding
- LF line endings
- a final newline
- spaces for indentation
- removal of trailing whitespace except in Markdown, where it can be meaningful
- four-space indentation for Python
- two-space indentation for YAML

EditorConfig does not replace Ruff, mypy, pytest, or pre-commit. Those tools remain responsible for formatting, linting, type checking, tests, and configured validation hooks.

## Python Environment

Python version and dependency state are controlled through `.python-version`, `pyproject.toml`, `uv.lock`, and uv. See [Development Tooling](development-tooling.md) for the established tooling commands.

## Local Validation

Use the existing repository validation sequence:

```console
uv lock --check
uv sync --group dev --group test
uv run ruff check .
uv run ruff format --check .
uv run mypy backend/tests
uv run --group test pytest
```

GitHub Actions supplies the remote Pull Request quality gate. See [Testing](testing.md) and the [Contributing Guide](../CONTRIBUTING.md) for the broader test and contribution workflow.

## Related Documentation

- [Security and Safe Data Handling Policy](../SECURITY.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [Development Tooling](development-tooling.md)
- [Testing](testing.md)
