# SOC Investigation Lab

SOC Investigation Lab is a hands-on, portfolio-oriented defensive-security project focused on Windows and Sysmon telemetry, alert triage, investigation, detection engineering, MITRE ATT&CK mapping, and escalation workflows. The repository is being built incrementally to model how a SOC Level 1 analyst turns security telemetry into an evidence-based decision.

The project favors transparent security logic, deterministic lab data, and explainable analyst reasoning over enterprise scale. It is not intended to be a production SIEM, EDR, or SOAR platform.

## Overview

A SOC analyst must understand why a detection fired, establish the relevant event context, gather evidence, identify indicators, reconstruct activity, decide whether the alert is a False Positive or True Positive, assess risk, and provide a useful escalation when required.

SOC Investigation Lab is designed to model that lifecycle in a small and understandable educational system. Its planned application capabilities will use controlled Windows Event Log and Sysmon examples so detection and investigation decisions can be reproduced and reviewed without live enterprise infrastructure.

The primary audience is SOC Level 1 analysts, junior blue-team analysts, and learners developing practical investigation skills. As later milestones add escalation outputs and executable detection rules, the project is intended to support higher-tier analysts reviewing escalation quality and detection-engineering learners examining rule behavior.

## Current Status

The repository is currently preparing **v0.1.0 — Project Foundation**. This milestone has not been released yet.

The engineering foundation is implemented, but the SOC application and its runtime processing pipeline are not implemented yet. Event processing begins in later milestones.

| Area | Status |
| --- | --- |
| Repository and module scaffold | Foundation implemented |
| Python 3.12 and uv configuration | Implemented |
| Ruff, mypy, and pre-commit tooling | Implemented |
| pytest foundation and smoke test | Implemented |
| GitHub Actions backend CI | Implemented |
| Scope, architecture, contribution, security, and local-development documentation | Implemented |
| Windows Event Log and Sysmon processing | Planned |
| Detection engine and executable detection rules | Planned |
| Alert management and analyst triage | Planned |
| Investigation, enrichment, verdict, and escalation workflows | Planned |
| Backend API, persistence, and analyst web interface | Planned |

## Goals

- Model a realistic SOC alert-investigation lifecycle for Level 1 and junior analysts.
- Practice analysis of controlled Windows Event Log and Sysmon telemetry.
- Build deterministic, reviewable detection logic that explains why an alert was generated.
- Demonstrate evidence collection, investigation reasoning, timelines, IOC handling, and MITRE ATT&CK mapping.
- Support structured False Positive and True Positive decisions and useful escalation handoffs.
- Maintain portfolio-quality engineering through tests, linting, formatting, type checking, CI, and documentation.
- Keep datasets synthetic, controlled-lab, or clearly safe for public reuse.
- Prefer simplicity and explainability over premature distributed architecture.

Detailed goals, boundaries, and non-goals are maintained in the [Project Scope](docs/project-scope.md).

## Architecture

### Planned application architecture

The planned backend is a modular monolith: one Python application and deployment unit with explicit internal boundaries for parsing, normalization, detection, alert handling, investigation, enrichment, persistence, and API concerns.

This approach keeps debugging and local execution straightforward, makes security decisions easier to inspect and test, and avoids infrastructure that is unnecessary for a portfolio lab. Module boundaries remain explicit so they can evolve when concrete requirements justify a change, without introducing speculative microservices.

The planned processing flow is:

```text
Raw Security Event
        ↓
      Parser
        ↓
 Normalized Event
        ↓
 Detection Engine
        ↓
 Detection Match
        ↓
       Alert
        ↓
      Triage
        ↓
  Investigation
        ↓
Evidence / IOC / Timeline / MITRE
        ↓
 FP / TP Verdict
        ↓
Severity / Priority
        ↓
    Escalation
```

This is a target logical flow, not a description of currently operational components. See [System Architecture](docs/architecture/overview.md) for component responsibilities and interaction rules.

## Features

### Foundation implemented

- Tracked repository scaffold for backend, frontend, rules, datasets, cases, documentation, scripts, and tests.
- Python 3.12 project metadata and reproducible dependency management with uv.
- Ruff linting, import sorting, and formatting checks.
- Strict mypy type-checking configuration.
- pytest test layout with one foundation smoke test.
- Local pre-commit validation hooks.
- Pull-request CI through the `Backend quality` check.
- Documented project scope, planned architecture, contribution workflow, security policy, and local-development conventions.

### Planned SOC capabilities

- Windows Event Log and Sysmon parsing and normalization.
- Transparent, rule-based detection evaluation with traceable detection matches.
- Alert creation, lifecycle management, and analyst triage.
- Investigation records containing evidence, related activity, timelines, and analyst notes.
- IOC extraction and contextual enrichment.
- Evidence-supported MITRE ATT&CK mappings.
- False Positive and True Positive verdicts with severity and priority assessment.
- Structured escalation reports and investigation cases.
- A backend API and analyst-focused web interface.

The planned capabilities above are roadmap targets and are not currently available as runnable application features.

## Investigation Workflow

The target analyst workflow is:

1. Receive a security event from controlled Windows or Sysmon telemetry.
2. Parse and normalize the source data into a consistent event representation.
3. Evaluate transparent detection rules and preserve why a rule matched.
4. Create and triage an analyst-facing alert.
5. Investigate related activity and collect relevant evidence.
6. Identify IOCs, reconstruct a timeline, and add supported MITRE ATT&CK context.
7. Record an evidence-driven False Positive or True Positive verdict.
8. Assess severity and operational priority.
9. Prepare escalation context and recommended actions when necessary.

This workflow is planned. The v0.1.0 foundation does not yet execute these steps.

## Detection Coverage

The repository reserves the following initial Windows detection categories under `rules/windows/`. The directories are foundation placeholders; no executable detection rules or coverage metrics exist yet.

| Category | Intended focus | Status |
| --- | --- | --- |
| `account/` | Account-related Windows activity | Planned |
| `execution/` | Suspicious process and command execution | Planned |
| `network/` | Security-relevant network activity | Planned |
| `persistence/` | Persistence-related Windows behavior | Planned |

Rule names, rule counts, and measurable coverage will be documented only when corresponding detections are implemented and tested.

## Repository Structure

| Path | Responsibility | Current state |
| --- | --- | --- |
| `backend/` | Planned Python backend modules plus the established backend test foundation | Application directories are placeholders; tests are partially established |
| `frontend/` | Planned analyst-facing web interface | Foundation placeholder |
| `rules/` | Planned transparent detection-rule library, initially for Windows | Foundation placeholders |
| `datasets/` | Future synthetic, controlled-lab, or public-safe telemetry | Foundation placeholders; no datasets included |
| `cases/` | Planned investigation scenarios and expected analyst outcomes | Foundation placeholder |
| `docs/` | Project scope, architecture, tooling, testing, security-related, and local-development guidance | Partially established |
| `scripts/` | Future narrowly scoped project and development utilities | Foundation placeholder |
| `tests/` | Shared fixtures and future cross-component integration tests | Foundation placeholders |
| `.github/` | Pull-request CI and future repository collaboration configuration | Backend CI implemented |

Placeholder directories describe intended ownership; they do not demonstrate completed functionality.

## Installation

### Prerequisites

- Git
- Python 3.12
- [uv](https://docs.astral.sh/uv/)

Clone the repository and install the current development and test dependencies:

```console
git clone https://github.com/emelianov-project/soc-investigation-lab.git
cd soc-investigation-lab
uv sync --group dev --group test
```

Optionally install the configured local hooks:

```console
uv run pre-commit install
```

There is currently no runnable SOC application in the v0.1.0 foundation, and no application-specific environment variables are required. Local configuration conventions are documented in [Local Development](docs/local-development.md).

## Development

Run the current local validation sequence before opening or updating a Pull Request:

```console
uv lock --check
uv sync --group dev --group test
uv run ruff check .
uv run ruff format --check .
uv run mypy backend/tests
uv run --group test pytest
```

Ruff provides linting and formatting validation, mypy performs static type checking, pytest runs the automated test suite, and pre-commit runs the configured Python quality hooks. GitHub Actions repeats the backend quality gates for Pull Requests targeting `main`.

See the [Contributing Guide](CONTRIBUTING.md), [Development Tooling](docs/development-tooling.md), and [Testing](docs/testing.md) for the established workflow and commands.

## Roadmap

| Milestone | Focus | Status |
| --- | --- | --- |
| v0.1.0 — Project Foundation | Repository, tooling, testing, CI, documentation, and safe local configuration | In progress |
| v0.2.0 — Event Processing | Windows and Sysmon parsing and normalized event contracts | Planned |
| v0.3.0 — Detection Engine | Detection-rule format, loading, evaluation, and initial rules | Planned |
| v0.4.0 — Alert Management | Alert generation, lifecycle, severity context, and triage queue | Planned |
| v0.5.0 — Investigation Workflow | Evidence, timelines, analyst notes, verdicts, and escalation | Planned |
| v0.6.0 — IOC & MITRE Enrichment | IOC handling and MITRE ATT&CK investigation context | Planned |
| v0.7.0 — Investigation Cases | Reproducible investigation scenarios and analyst outcomes | Planned |
| v0.8.0 — Web Interface | Analyst-focused alert and investigation experience | Planned |
| v0.9.0 — Hardening & Documentation | Security, reliability, documentation, and portfolio refinement | Planned |
| v1.0.0 — Portfolio Release | Coherent end-to-end portfolio release | Planned |

Roadmap entries describe planned work, not released or implemented capabilities. No milestone dates are implied.

## Documentation

- [Project Scope](docs/project-scope.md) — purpose, users, product boundaries, and non-goals.
- [System Architecture](docs/architecture/overview.md) — planned components, responsibilities, and data flow.
- [Contributing Guide](CONTRIBUTING.md) — Issue, branch, validation, Pull Request, and merge workflow.
- [Security and Safe Data Handling Policy](SECURITY.md) — public-repository data and reporting requirements.
- [Development Tooling](docs/development-tooling.md) — Ruff, mypy, and pre-commit commands.
- [Testing](docs/testing.md) — pytest layout and test commands.
- [Local Development](docs/local-development.md) — environment-file and editor conventions.

## Security and Data Policy

Only synthetic data, telemetry produced in a controlled lab, or public data that is clearly safe and permitted for reuse may be introduced. Do not commit credentials, secrets, personal data, confidential enterprise information, real employer or client telemetry, production logs, or executable malware.

Review the [Security and Safe Data Handling Policy](SECURITY.md) before contributing telemetry, fixtures, screenshots, datasets, or investigation artifacts.

## License

SOC Investigation Lab is available under the [MIT License](LICENSE).
