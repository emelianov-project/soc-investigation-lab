# Changelog

All notable changes to SOC Investigation Lab will be documented in this file.

The format is inspired by Keep a Changelog, and this project follows
Semantic Versioning.

## [Unreleased]

## [0.4.0] - 2026-11-06

### Added

- Typed Alert domain models with explicit identity, lifecycle state, severity, priority, and timestamps.
- Detached `DetectionMatch` evidence with the full normalized event and ordered condition trace.
- Deterministic Alert creation with caller-supplied IDs and timezone-aware timestamps.
- Alert lifecycle operations for acknowledgement and closure.
- Independent severity and priority management for active Alerts.
- Stateless in-process Alert queue with typed filters and deterministic ordering.
- XML-to-Alert integration and failure-path coverage for the six existing detection rules.
- Alert Management architecture documentation and an offline example.

### Changed

- Shared Alert snapshot and timestamp validation across Alert operations.

### Fixed

- Strict validation of match evidence and safe, controlled failure diagnostics.
- Rejection of malformed Alert snapshots before transitions, policy updates, or queue filtering.

## [0.3.0] - 2026-09-27

### Added

- Typed `DetectionRule`, recursive condition, `ConditionTrace`, and `DetectionMatch` contracts.
- Deterministic safe YAML rule loading with path containment and duplicate-ID rejection.
- Explicit normalized-event field resolution and 15 typed comparison operators.
- Three-valued condition evaluation with complete, ordered explanation traces.
- Stateless single-event Detection Engine with category/source targeting and rule-ID-ordered matches.
- Six initial declarative Windows/Sysmon rules with synthetic positive, negative, and optional-data tests.
- XML-to-`DetectionMatch` integration, deterministic ordering, and failure-path coverage.
- Detection Engine architecture and rule-authoring documentation.

### Changed

- Shared field/type semantics validate rules at load time as well as during evaluation.

### Fixed

- Semantically invalid YAML rules are rejected before evaluation, including incompatible category/field/operator combinations and malformed typed literals; runtime checks remain defense in depth.

## [0.2.0] - 2026-09-25

### Added

- Typed normalized-event domain models and Windows Event XML ingestion for one record at a time.
- Windows Security normalization for Events 4624, 4625, and 4688.
- Sysmon normalization for Events 1, 3, 11, and 22.
- Explicit parser registry and XML-to-normalized-event pipeline.
- Synthetic Windows Security and Sysmon fixtures, with integration and failure-path coverage.
- Implemented event-processing architecture documentation and examples.

### Changed

- Aligned strict mypy backend import resolution across direct checks and pre-commit.

## [0.1.0] - 2026-09-10

### Added

- Initial repository scaffold for backend, frontend, rules, datasets, investigation cases,
  documentation, scripts, and tests.
- Python 3.12 project configuration.
- uv-based reproducible dependency management.
- Ruff linting and formatting configuration.
- Strict mypy static type checking.
- pre-commit validation hooks.
- pytest test foundation and smoke test.
- Pull-request GitHub Actions backend quality CI.
- Project scope and non-goals documentation.
- Planned modular-monolith system architecture documentation.
- Contribution and development workflow documentation.
- Security and safe-data handling policy.
- Local development environment configuration and documentation.
- Portfolio-ready project README.
