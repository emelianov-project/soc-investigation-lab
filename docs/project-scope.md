# Project Scope

## Purpose

SOC Investigation Lab is a hands-on defensive-security project that models the investigation lifecycle followed by a security operations center (SOC) analyst handling Windows security alerts. It is intended to provide a controlled environment for learning and demonstrating security-event processing, detection, alert triage, investigation, evidence collection, indicator of compromise (IOC) handling, MITRE ATT&CK mapping, analyst verdicts, and escalation.

The project emphasizes an analyst's reasoning and investigation workflow rather than enterprise-scale telemetry collection. It is an educational and portfolio project, not a production security product.

## Target User

The primary users are:

- SOC Level 1 analysts;
- junior blue-team and security analysts; and
- learners developing practical SOC investigation skills.

Secondary users may include SOC Level 2 analysts reviewing escalations, learners practicing detection engineering, and security professionals reviewing investigation methodology. The project is not a replacement for commercial SOC platforms or the operational controls those platforms provide.

## Target SOC Level 1 Workflow

The intended workflow is conceptual and follows this lifecycle:

Security telemetry
→ Event normalization
→ Detection rule evaluation
→ Alert creation
→ Initial triage
→ Investigation
→ Evidence, IOC, and timeline analysis
→ MITRE ATT&CK mapping
→ False Positive or True Positive verdict
→ Severity and priority assessment
→ Escalation and recommended actions

Within this workflow, the analyst is expected to:

1. Review normalized security telemetry and understand the event context that caused a detection rule to match.
2. Triage the resulting alert by checking its source, timing, severity, affected entities, and available context.
3. Investigate related activity, collect relevant evidence, identify IOCs, and reconstruct a concise event timeline.
4. Map observed behavior to applicable MITRE ATT&CK techniques when the available evidence supports that mapping.
5. Reach an evidence-driven False Positive or True Positive verdict and assess severity and operational priority.
6. Document the reasoning, recommended actions, and escalation context needed by a higher-tier analyst.

This workflow defines analyst outcomes only. Detailed implementation architecture, APIs, storage models, and module internals are outside this document.

## Project Goals

1. Reproduce a realistic SOC Level 1 investigation workflow.
2. Provide deterministic, understandable security telemetry that can be inspected and investigated.
3. Build transparent detection logic that can be reviewed and tested.
4. Help analysts understand why an alert was generated.
5. Support evidence-driven False Positive and True Positive decisions.
6. Support investigation timelines, IOC identification, and MITRE ATT&CK mapping.
7. Produce structured escalation information suitable for handoff to a higher-tier analyst.
8. Maintain a portfolio-quality codebase with testing, linting, type checking, continuous integration, and documentation.
9. Keep the project small enough for its security logic and investigation decisions to remain understandable instead of evolving into an enterprise platform.

## Telemetry Direction

The initial telemetry focus is Windows Event Logs and Sysmon telemetry. The project is intended to begin with synthetic events, sanitized sample events, and telemetry generated in controlled lab environments. Initial ingestion should favor files, test fixtures, and controlled datasets so investigations remain deterministic and reproducible without requiring live enterprise infrastructure.

Future ingestion mechanisms may evolve as the roadmap progresses, but the project will remain centered on investigation rather than general-purpose log collection. Test and sample telemetry must not include production secrets, credentials, personal data, or confidential enterprise telemetry. This scope document introduces no datasets.

## Project Boundaries

Intended project capabilities may include:

- Windows and Sysmon event parsing;
- normalized event schemas;
- transparent, rule-based detections;
- alert generation and triage;
- investigation records and analyst notes;
- IOC extraction and enrichment;
- MITRE ATT&CK mappings;
- related-event timelines;
- severity and priority assessment;
- False Positive and True Positive verdicts;
- structured escalation reports;
- controlled sample datasets;
- a backend API; and
- an analyst-focused web interface.

These are intended capabilities, not a statement that they are currently implemented. Their delivery is governed by the project roadmap and subsequent milestones.

The project prioritizes explainability, deterministic behavior, reproducible investigations, educational value, testability, and maintainability over enterprise scale, feature count, or ingestion volume.

## Non-Goals

### A full SIEM

SOC Investigation Lab is not intended to become a full security information and event management (SIEM) platform. It will not attempt to provide enterprise-scale log collection, arbitrary log-source onboarding, massive distributed storage, long-term enterprise log retention, enterprise search at SIEM scale, or large-scale correlation across arbitrary organizations.

### An EDR

SOC Investigation Lab is not intended to become an endpoint detection and response (EDR) product. It will not provide an endpoint agent, kernel-level telemetry collection, process blocking, endpoint isolation, malware prevention, or endpoint remediation.

### A SOAR platform

SOC Investigation Lab is not intended to become a security orchestration, automation, and response (SOAR) platform. It will not provide general-purpose orchestration, arbitrary third-party automation workflows, automatic containment across enterprise infrastructure, a large integration marketplace, or autonomous remediation.

The project is also not intended to provide production-grade multi-tenancy, enterprise identity management, enterprise role-based access control, high availability, distributed clustering, petabyte-scale storage, production service-level guarantees, commercial threat-intelligence platform functionality, or a replacement for professional SIEM, EDR, or SOAR products.

## Current Implementation Status

At the current Project Foundation milestone, the repository contains engineering infrastructure rather than the SOC application functionality described above. The implemented foundation consists of the repository structure, Python project configuration, uv dependency management, development tooling, an automated test foundation, and GitHub Actions continuous integration.

Event processing, normalization, detection, alert management, investigation workflows, enrichment, investigation cases, the backend API, and the analyst web interface are planned for subsequent milestones. Planned capabilities in this document must not be interpreted as currently available functionality.

