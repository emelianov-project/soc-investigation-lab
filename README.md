# SOC Investigation Lab

SOC Investigation Lab is a hands-on, portfolio-oriented defensive-security project focused on Windows and Sysmon telemetry, alert triage, investigation, detection engineering, MITRE ATT&CK mapping, and escalation workflows. The repository is being built incrementally to model how a SOC Level 1 analyst turns security telemetry into an evidence-based decision.

The project favors transparent security logic, deterministic lab data, and explainable analyst reasoning over enterprise scale. It is not intended to be a production SIEM, EDR, or SOAR platform.

## Overview

A SOC analyst must understand why a detection fired, establish the relevant event context, gather evidence, identify indicators, reconstruct activity, decide whether the alert is a False Positive or True Positive, assess risk, and provide a useful escalation when required.

SOC Investigation Lab is designed to model that lifecycle in a small and understandable educational system. Its implemented event-processing and detection layers use controlled Windows Event Log and Sysmon examples to produce explainable detection matches. Alert handling and investigation decisions remain later milestones.

The primary audience is SOC Level 1 analysts, junior blue-team analysts, and learners developing practical investigation skills. Detection-engineering learners can inspect the initial rule library and its explanations. Later milestones will add escalation outputs for higher-tier analysts reviewing escalation quality.

## Current Status

The repository has released **v0.1.0 — Project Foundation**, **v0.2.0 — Event Processing**, and **v0.3.0 — Detection Engine**. Windows Event XML ingestion and normalization for seven supported Windows Security and Sysmon event identities feed an operational, deterministic Detection Engine. Safe rule loading includes structural and semantic validation; six initial rules and XML-to-`DetectionMatch` integration are implemented and tested. Alert handling and investigation remain planned.

| Area | Status |
| --- | --- |
| Repository and module scaffold | Foundation implemented |
| Python 3.12 and uv configuration | Implemented |
| Ruff, mypy, and pre-commit tooling | Implemented |
| Parser, detection, rule-library, and XML-to-match integration/failure-path tests | Implemented |
| GitHub Actions backend CI | Implemented |
| Scope, architecture, contribution, security, and local-development documentation | Implemented |
| Windows Event XML ingestion and Security/Sysmon normalization | Implemented for seven supported events |
| Typed normalized contexts, parser registry, and normalization pipeline | Implemented |
| Detection Engine, semantic rule validation, and complete condition traces | Released in v0.3.0 |
| Initial declarative detection-rule library | Six rules implemented and tested |
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

### Application architecture

The planned backend is a modular monolith: one Python application and deployment unit with explicit internal boundaries for parsing, normalization, detection, alert handling, investigation, enrichment, persistence, and API concerns.

This approach keeps debugging and local execution straightforward, makes security decisions easier to inspect and test, and avoids infrastructure that is unnecessary for a portfolio lab. Module boundaries remain explicit so they can evolve when concrete requirements justify a change, without introducing speculative microservices.

The implemented path extends the released v0.2.0 event-processing prefix with the released v0.3.0 detection layer:

`Windows Event XML → RawWindowsEvent → Parser Registry → Source Normalizer → NormalizedEvent → Detection Engine → DetectionMatch`

The wider target processing flow continues from `DetectionMatch` into planned stages:

```text
 DetectionMatch (implemented boundary)
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

Parsing, normalization, and detection through `DetectionMatch` are operational. An Alert is not a detection match: Alert generation and all later stages remain planned. See [Event Processing Architecture](docs/architecture/event-processing.md) for the v0.2.0 layer, [Detection Engine Architecture](docs/architecture/detection-engine.md) for the current output boundary, and [System Architecture](docs/architecture/overview.md) for the wider plan.

## Features

### Foundation implemented

- Tracked repository scaffold for backend, frontend, rules, datasets, cases, documentation, scripts, and tests.
- Python 3.12 project metadata and reproducible dependency management with uv.
- Ruff linting, import sorting, and formatting checks.
- Strict mypy type-checking configuration.
- pytest test layout and foundation smoke test.
- Local pre-commit validation hooks.
- Pull-request CI through the `Backend quality` check.
- Documented project scope, planned architecture, contribution workflow, security policy, and local-development conventions.

### Event processing implemented for v0.2.0

- Ingestion of one namespaced Windows Event XML record at a time.
- Windows Security Events 4624, 4625, and 4688 and Sysmon Events 1, 3, 11, and 22 normalized into typed event contexts.
- Explicit parser registry and public XML-to-`NormalizedEvent` pipeline.
- Synthetic fixtures, focused parser tests, and end-to-end integration and failure-path tests.

This event-processing implementation was released in v0.2.0.

### Detection Engine released in v0.3.0

- Typed `DetectionRule`, `ConditionTrace`, and `DetectionMatch` contracts.
- Deterministic safe YAML loading, semantic field/type validation, and duplicate-ID rejection.
- Explicit field resolution, 15 typed operators, and complete three-valued condition traces.
- Stateless single-event evaluation with category/source targeting and rule-ID-ordered matches.
- Six initial declarative Windows rules with synthetic positive/negative tests.
- Offline XML-to-match integration, optional-data, determinism, and failure-path coverage.

This implementation ends at `DetectionMatch`; it does not decide maliciousness or create Alerts.

### Planned downstream SOC capabilities

- Alert creation, lifecycle management, and analyst triage.
- Investigation records containing evidence, related activity, timelines, and analyst notes.
- IOC extraction and contextual enrichment.
- Evidence-supported MITRE ATT&CK mappings.
- False Positive and True Positive verdicts with severity and priority assessment.
- Structured escalation reports and investigation cases.
- A backend API and analyst-focused web interface.

The downstream capabilities above are roadmap targets and are not currently runnable.

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

Steps 2 and 3 are implemented for the seven supported XML event identities and the initial rule library. Step 1 uses controlled fixture/file input, not live collection. Alert creation and steps 4–9 remain planned.

## Detection Coverage

The initial library contains exactly six tested declarative rules under `rules/windows/`. These are educational single-event triage signals, not enterprise coverage metrics or proof of maliciousness.

| Directory | Current rules | Count |
| --- | --- | --- |
| `account/` | `failed-remote-authentication` | 1 |
| `execution/` | `certutil-suspicious-arguments`, `powershell-encoded-command` | 2 |
| `network/` | `dns-suspicious-query-marker`, `powershell-network-connection` | 2 |
| `persistence/` | `startup-folder-file-activity` | 1 |

See the [rule inventory and limitations](docs/architecture/detection-engine.md#initial-windows-rule-library) and [rule-authoring guide](docs/detections/rule-authoring.md). Exact case-sensitive markers can miss variants, and legitimate activity can match.

## Repository Structure

| Path | Responsibility | Current state |
| --- | --- | --- |
| `backend/` | Python event processing, detection, and backend tests | Event-processing and detection layers implemented; downstream modules remain placeholders |
| `backend/app/models/` | Event, rule, condition, trace, and match contracts | Implemented |
| `backend/app/detection/` | Safe loading, shared semantics, evaluator, and single-event engine | Released in v0.3.0 |
| `frontend/` | Planned analyst-facing web interface | Foundation placeholder |
| `rules/windows/` | Transparent declarative Windows rule library | Six tested rules |
| `datasets/` | Future synthetic, controlled-lab, or public-safe telemetry | Foundation placeholders; no datasets included |
| `cases/` | Planned investigation scenarios and expected analyst outcomes | Foundation placeholder |
| `docs/` | Scope, architecture, rule authoring, tooling, testing, security, and local-development guidance | Event-processing and Detection Engine boundaries documented |
| `scripts/` | Future narrowly scoped project and development utilities | Foundation placeholder |
| `tests/fixtures/` | Synthetic Windows/Sysmon XML input | Seven supported event fixtures |
| `tests/integration/` | Cross-component normalization and detection validation | XML-to-event and XML-to-match tests implemented |
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
uv sync --locked --group dev --group test
```

Optionally install the configured local hooks:

```console
uv run pre-commit install
```

There is no runnable end-to-end analyst SOC application yet. XML normalization, rule loading, and single-event detection are available as Python functions, not an application CLI or API. See the [Python integration example](docs/architecture/detection-engine.md#python-integration-example). No application-specific environment variables are required; local conventions are documented in [Local Development](docs/local-development.md).

## Development

Run the current local validation sequence before opening or updating a Pull Request:

```console
uv lock --check
uv sync --locked --group dev --group test
git diff --check
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy backend/tests
uv run --no-sync mypy tests/integration
uv run --no-sync pytest
uv run --no-sync pre-commit run --all-files
```

Ruff provides linting and formatting validation, mypy performs static type checking, pytest runs the automated test suite, and pre-commit runs the configured Python quality hooks. GitHub Actions repeats the backend quality gates for Pull Requests targeting `main`.

See the [Contributing Guide](CONTRIBUTING.md), [Development Tooling](docs/development-tooling.md), and [Testing](docs/testing.md) for the established workflow and commands.

## Roadmap

| Milestone | Focus | Status |
| --- | --- | --- |
| v0.1.0 — Project Foundation | Repository, tooling, testing, CI, documentation, and safe local configuration | Released |
| v0.2.0 — Event Processing | Windows and Sysmon XML parsing and normalized event contracts | Released |
| v0.3.0 — Detection Engine | Detection-rule format, safe/semantic loading, evaluation, and six initial rules | Released |
| v0.4.0 — Alert Management | Alert generation, lifecycle, severity context, and triage queue | Planned |
| v0.5.0 — Investigation Workflow | Evidence, timelines, analyst notes, verdicts, and escalation | Planned |
| v0.6.0 — IOC & MITRE Enrichment | IOC handling and MITRE ATT&CK investigation context | Planned |
| v0.7.0 — Investigation Cases | Reproducible investigation scenarios and analyst outcomes | Planned |
| v0.8.0 — Web Interface | Analyst-focused alert and investigation experience | Planned |
| v0.9.0 — Hardening & Documentation | Security, reliability, documentation, and portfolio refinement | Planned |
| v1.0.0 — Portfolio Release | Coherent end-to-end portfolio release | Planned |

Status distinguishes implemented work from published releases and future plans. No milestone dates are implied.

## Documentation

- [Project Scope](docs/project-scope.md) — purpose, users, product boundaries, and non-goals.
- [System Architecture](docs/architecture/overview.md) — implemented and planned components, responsibilities, and data flow.
- [Event Processing Architecture](docs/architecture/event-processing.md) — implemented v0.2.0 pipeline and examples.
- [Detection Engine Architecture](docs/architecture/detection-engine.md) — released v0.3.0 loading, semantics, evaluation, and `DetectionMatch` boundary.
- [Rule Authoring](docs/detections/rule-authoring.md) — supported fields/operators, safe examples, validation, and testing.
- [v0.2.0 Release Notes](docs/releases/v0.2.0.md) — published event-processing release scope, validation, and limitations.
- [v0.3.0 Release Notes](docs/releases/v0.3.0.md) — published Detection Engine release scope, validation, and limitations.
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
