# v0.2.0 Event Processing Scope and Contracts

## Status

This document defines the implementation contract for **v0.2.0 — Event Processing**.
Event-processing runtime functionality is not yet implemented at the time this document is
introduced, and v0.2.0 has not been released.

The contract constrains the implementation work in Issues #28 through #34. Issue #35 will
later document the implemented event-processing architecture and representative examples,
while Issue #36 will prepare the milestone's release artifacts. This document describes
required behavior and boundaries, not completed functionality.

## Purpose

v0.2.0 establishes a reliable boundary between raw Windows telemetry and future downstream
security logic. It defines which records may enter the pipeline, the information that must be
retained, the normalized semantics that supported records must produce, and the failures that
must remain explicit.

The intended logical flow is:

`Windows Event XML → Raw Event Envelope → Source Parser → NormalizedEvent`

This milestone ends at a valid `NormalizedEvent`. Detection rules and detection evaluation
begin in the future **v0.3.0 — Detection Engine** milestone.

## Supported Event Matrix

The supported set for v0.2.0 is closed:

| Source | Provider | Channel | Event ID | Meaning | Normalized Category |
| --- | --- | --- | ---: | --- | --- |
| Windows Security | `Microsoft-Windows-Security-Auditing` | `Security` | 4624 | Successful Logon | `authentication` |
| Windows Security | `Microsoft-Windows-Security-Auditing` | `Security` | 4625 | Failed Logon | `authentication` |
| Windows Security | `Microsoft-Windows-Security-Auditing` | `Security` | 4688 | Process Creation | `process` |
| Sysmon | `Microsoft-Windows-Sysmon` | `Microsoft-Windows-Sysmon/Operational` | 1 | Process Creation | `process` |
| Sysmon | `Microsoft-Windows-Sysmon` | `Microsoft-Windows-Sysmon/Operational` | 3 | Network Connection | `network` |
| Sysmon | `Microsoft-Windows-Sysmon` | `Microsoft-Windows-Sysmon/Operational` | 11 | File Create | `file` |
| Sysmon | `Microsoft-Windows-Sysmon` | `Microsoft-Windows-Sysmon/Operational` | 22 | DNS Query | `dns` |

Unsupported providers and Event IDs must not silently fall back to a generic supported event.
Adding another provider or Event ID requires separately scoped work after this contract is
updated or superseded.

## Input Boundary

Windows Event XML is the only ingestion boundary for v0.2.0. The implementation consumes one
Windows Event XML record at a time and produces either one valid normalized event or one
explicit failure.

The following inputs are outside this milestone:

- binary `.evtx` files;
- live Windows Event Log subscriptions;
- SIEM or EDR ingestion;
- network ingestion; and
- arbitrary log-source formats.

A future `.evtx` adapter may emit the same XML or raw-event representation without changing
the normalization contracts defined here. The adapter itself is not part of v0.2.0.

## Raw Event Envelope

The raw event envelope is the conceptual typed representation produced after XML ingestion and
before source-specific normalization. It retains the source-shaped values needed by a source
parser without making detection or investigation decisions.

Required common metadata is:

- provider;
- event ID;
- channel;
- timestamp; and
- computer.

Event record ID is optional common metadata. Named `EventData` fields are retained as
source-shaped values.

### Provider

The provider is a non-empty source identity taken from the Windows Event `System` section. It
participates, together with the channel and Event ID, in deterministic source and parser
selection.

### Event ID

The Event ID is a positive integer taken from `System/EventID`. An absent, non-integer, zero,
or negative value is invalid raw-event metadata.

### Channel

The channel is a non-empty channel name taken from `System/Channel`. The supported matrix
defines the provider and channel combinations accepted by v0.2.0.

### Timestamp

The timestamp is a timezone-aware event time derived from
`System/TimeCreated/@SystemTime`. The implementation must normalize it internally without
inventing a timestamp when the source value is absent or invalid.

### Computer

The computer is a non-empty originating computer or host value taken from `System/Computer`.
It identifies the system that emitted the record; it is not inferred from local execution
context.

### Event Record ID

The event record ID is an integer when present. It remains optional because normalization must
not invent a record ID when the source record omits one.

### EventData

Named `EventData` values retain their source-facing meaning until a source parser interprets
them. Ingestion must:

- preserve named source fields;
- avoid inventing absent keys;
- avoid silently discarding unknown named fields; and
- expose structurally invalid named data as an explicit raw-event failure.

This contract does not prescribe an exact Python class for the raw event envelope.

## Event Source

The normalized source values for v0.2.0 are exactly:

- Windows Security; and
- Sysmon.

Source identity is derived deterministically from the supported provider and channel context.
The contract does not accept arbitrary user-provided source strings.

## Normalized Event

`NormalizedEvent` is the conceptual common contract returned by successful v0.2.0 event
processing. Its required common metadata is:

- source;
- provider;
- event ID;
- channel;
- timestamp;
- computer; and
- category.

Event record ID is optional common metadata. Each event also contains one typed,
category-specific context appropriate to its normalized category and a controlled
`source_data` representation for relevant source fields that have no normalized equivalent.

Issue #28 may refine the exact Python and Pydantic field names, but its implementation must
preserve the semantics and required-versus-optional distinctions defined here.

## Normalized Categories

v0.2.0 defines exactly these normalized categories:

- `authentication`;
- `process`;
- `network`;
- `file`; and
- `dns`.

Alert, detection, incident, investigation, IOC, and MITRE concepts are not event categories.
They belong to later processing stages or milestones.

## Category-Specific Contexts

### Authentication

Authentication context must be capable of representing:

- outcome as success or failure;
- user, when present;
- domain, when present;
- logon type, when present;
- source IP address, when present;
- source port, when present; and
- workstation or source-host metadata, when present.

The context supports Windows Security Event IDs 4624 and 4625. Provider-specific failure data
that has no common field remains available through controlled source data.

### Process

Process context must be capable of representing:

- process ID, when present;
- process image, path, or process name;
- command line, when present;
- parent process ID, when present;
- parent image or path, when present; and
- user or security context, when present.

The context supports Windows Security Event ID 4688 and Sysmon Event ID 1. The contract does
not require the two providers to expose identical raw fields.

### Network

Network context must be capable of representing:

- protocol, when present;
- source IP address;
- source port;
- destination IP address;
- destination port;
- related process ID, when present; and
- related process image, when present.

This category initially supports Sysmon Event ID 3.

### File

File context must be capable of representing:

- target file path;
- related process ID, when present; and
- related process image, when present.

This category initially supports Sysmon Event ID 11.

### DNS

DNS context must be capable of representing:

- query name;
- query status, when present;
- query result data, when present;
- related process ID, when present; and
- related process image, when present.

This category initially supports Sysmon Event ID 22.

## Required and Optional Field Rules

The following rules apply to every supported parser and normalized context:

1. A field is required only when the normalized contract cannot be meaningful without it.
2. Source fields that are absent remain absent or optional.
3. Parsers must not invent placeholder usernames, hosts, IP addresses, ports, process IDs,
   paths, or timestamps.
4. Missing data must not be interpreted as a detection conclusion.
5. Parser-specific conversions must be deterministic.
6. Invalid typed values must not be silently coerced into unrelated defaults.
7. Source-specific sentinel handling, when implementation introduces it, must be explicit and
   tested.
8. Normalization must not manufacture evidence that was not present in the source event.

## Source-Data Preservation

`source_data` is the controlled representation of relevant named, source-specific `EventData`
values that have no normalized equivalent yet, remain useful for traceability, and are safe to
retain.

The following constraints apply:

- normalized fields remain authoritative for downstream common semantics;
- `source_data` is not a replacement for normalized fields;
- source-data retention must not weaken typed validation of normalized fields;
- unknown named fields must not be discarded solely because v0.2.0 does not normalize them;
- raw XML need not be duplicated into every normalized event unless later scoped work
  justifies it; and
- source data in public fixtures and examples must satisfy the project's safe-data policy.

This document does not prescribe a database representation.

## Error Semantics

v0.2.0 defines four conceptual failure classes. Implementations may refine the exact Python
exception names while preserving these public semantics.

### Malformed Input

Examples include invalid XML or XML that cannot be parsed. Processing must fail explicitly and
must not return a partial `NormalizedEvent`.

### Invalid Raw Event

Examples include:

- missing required `System` metadata;
- invalid Event ID representation;
- invalid timestamp; and
- structurally invalid named `EventData`.

Processing must expose a controlled parsing or validation failure. Accidental low-level XML
library behavior must not become the public error contract, and no partial normalized event is
returned.

### Unsupported Event

Examples include an unsupported provider, a supported provider with an unsupported Event ID,
or another unsupported provider/Event-ID identity. Processing must produce a deterministic,
explicit unsupported-event result or error. There is no generic fallback parser and no silent
acceptance.

### Invalid Normalized Value

Examples include:

- an invalid process identifier after a required conversion;
- an invalid IP address where typed IP validation applies;
- an invalid port where typed port validation applies; and
- a normalized object that violates its domain contract.

Processing must fail through explicit normalization or validation semantics and must not
substitute invented fallback values.

Issues #30 through #34 will implement and test these failure semantics.

## Determinism and Purity Expectations

Event processing in v0.2.0 must be:

- deterministic for identical input;
- offline;
- independent from external network services;
- independent from threat intelligence;
- independent from database state;
- free from detection decisions; and
- free from alert-lifecycle decisions.

The same valid input must produce the same normalized semantic result.

## Safe Data Requirements

All fixtures, examples, and source-data values must follow the
[Security and Safe Data Handling Policy](../SECURITY.md).

Allowed sources are:

- fully synthetic telemetry;
- controlled lab-generated telemetry created specifically for testing; and
- clearly public-safe, reusable samples where redistribution is permitted.

Prohibited material includes:

- real employer or client telemetry;
- production Windows or Sysmon logs;
- SIEM or EDR exports;
- credentials or secrets;
- personal data;
- confidential infrastructure identifiers; and
- executable malware.

Manually redacted employer, client, corporate, or production logs remain prohibited. Examples
should use reserved documentation values such as `example.com`, `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.

This Issue introduces no telemetry fixtures.

## Relationship to v0.3.0 Detection Engine

v0.2.0 outputs valid normalized events. The future v0.3.0 Detection Engine may consume those
events and must not require direct interpretation of raw Windows XML for the supported v0.2.0
event set.

The conceptual boundary is:

`Raw source details → v0.2.0 parsing and normalization → stable normalized semantics → v0.3.0 detection`

This document does not define detection-rule syntax and does not claim that the Detection
Engine exists.

## Explicit Non-Goals

The following are explicitly outside v0.2.0:

- binary `.evtx` parsing;
- live Windows Event Log collection;
- detection rules;
- a detection engine;
- alert generation;
- alert lifecycle;
- analyst triage;
- investigation workflow;
- IOC extraction or enrichment;
- MITRE ATT&CK runtime enrichment;
- severity decisions;
- priority decisions;
- escalation;
- persistence or a database;
- FastAPI endpoints;
- a web UI;
- Kafka or other message brokers;
- background workers;
- microservices;
- Kubernetes;
- production ingestion;
- arbitrary log-source support; and
- employer or client telemetry.

These exclusions keep v0.2.0 focused on one reliable transformation boundary. They preserve
the repository's modular-monolith direction and prevent event processing from expanding into
SIEM, EDR, SOAR, or speculative distributed-system functionality.

## Implementation Mapping

The existing v0.2.0 backlog maps to this contract as follows:

- Issue #28 — normalized event domain models;
- Issue #29 — synthetic Windows and Sysmon fixtures;
- Issue #30 — Windows Event XML ingestion;
- Issue #31 — Windows Security normalization;
- Issue #32 — Sysmon normalization;
- Issue #33 — parser registry and normalization pipeline;
- Issue #34 — integration and failure-path testing;
- Issue #35 — implemented architecture and examples; and
- Issue #36 — release preparation.

This document is the scope baseline those Issues must remain consistent with. Later work may
refine implementation details, but any material expansion of providers, Event IDs, normalized
semantics, or milestone boundaries requires separately scoped review.

