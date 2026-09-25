# v0.3.0 Detection Engine Scope and Contracts

## Status and boundary

This document defines the contract for the planned **v0.3.0 — Detection
Engine** milestone. It does not describe an implemented runtime or a published
v0.3.0 release. The released v0.2.0 pipeline supplies validated
[`NormalizedEvent`](../backend/app/models/normalized_event.py) objects; v0.3.0
is responsible only for evaluating declarative rules and returning zero or
more explainable matches:

`NormalizedEvent → DetectionRule evaluation → zero or more DetectionMatch objects`

The output boundary is `DetectionMatch`. Producing an Alert or making an
analyst decision belongs to later milestones. See the
[event-processing architecture](architecture/event-processing.md) for the
implemented input contract.

## Rule format and identity

A `DetectionRule` is data, separate from the evaluation runtime. The initial
format is one UTF-8 YAML mapping per `.yaml` or `.yml` file in the versioned
`rules/windows/` library. Its closed top-level schema is:

| Key | Contract |
| --- | --- |
| `id` | Required, stable, repository-wide unique lowercase slug (`[a-z0-9]+(?:-[a-z0-9]+)*`); changing its meaning requires a new ID. |
| `version` | Required positive integer, increased when criteria are revised without changing the rule's identity. |
| `title` | Required non-empty human-readable name. |
| `description` | Required non-empty explanation of the behavior being selected, not a claim that an alert or verdict exists. |
| `categories` | Required non-empty, duplicate-free list of supported `EventCategory` values; only events in these categories are candidates. |
| `sources` | Optional non-empty, duplicate-free list of supported `EventSource` values; when omitted, either supported source may be a candidate. Required when a condition uses `source_data.*`. |
| `condition` | Required root of the condition tree defined below. |

Current categories are `authentication`, `process`, `network`, `file`, and
`dns`; current sources are `windows_security` and `sysmon`. Values must use
their declared enum strings. Unknown keys, duplicate mapping keys, empty
required values, unsupported enum values, and duplicate IDs are invalid rules.
Rule metadata does not assign alert severity, priority, or workflow state.

For example, this illustrative rule matches a Security 4688 process event
whose normalized image ends in a specified path suffix. It is not a claim of
maliciousness or a production-ready detection:

```yaml
id: example-security-process
version: 1
title: Example Security process event
description: Illustrate matching a normalized process image.
categories: [process]
sources: [windows_security]
condition:
  all:
    - field: event_id
      op: equals
      value: 4688
    - field: context.image
      op: ends_with
      value: '\cmd.exe'
```

## Condition tree

Each node has exactly one shape, with no extra keys:

- A leaf is `{field: <path>, op: <operator>, value: <literal>}`. The `value`
  key is omitted for `exists` and `not_exists` and required for every other
  operator. YAML null is not a comparison literal; use an existence operator.
- `all` has a non-empty ordered list of child nodes. It is true only when
  every child is true.
- `any` has a non-empty ordered list of child nodes. It is true when at least
  one child is true.
- `not` has exactly one child node and reverses only a definite true or false
  result.

The tree is finite, with maximum nesting depth 8 and at most 64 leaves per
rule. A rule exceeding either limit is invalid at load time. Child order is
preserved for the explanation trace, but evaluation does not short-circuit:
every child is evaluated in order so identical inputs produce identical,
complete traces.

Condition evaluation uses three outcomes: `true`, `false`, and `unknown`.
`unknown` means a valid path had no usable value for this event; it is not a
match. This prevents negation from turning absent evidence into a positive
finding:

| Node | True | False | Unknown |
| --- | --- | --- | --- |
| `all` | All children true | Any child false | Otherwise, at least one child unknown |
| `any` | Any child true | All children false | Otherwise, at least one child unknown |
| `not` | Child false | Child true | Child unknown |

An event produces one `DetectionMatch` for a rule only when its root is
`true`. A root of `false` or `unknown` produces no match.

## Field paths and resolution

Paths are case-sensitive, dot-separated data paths, not Python expressions.
They allow no indexes, wildcards, method calls, object traversal, or implicit
fallback to raw XML. The only path forms are:

| Form | Allowed values and validation |
| --- | --- |
| Common field | Exactly `source`, `provider`, `event_id`, `channel`, `timestamp`, `computer`, `record_id`, or `category`. |
| `context.<field>` | Exactly one declared field of the typed context for **every** targeted category; its type must be compatible across those categories. For example, `context.image` is valid for `process`, not `dns`. |
| `source_data.<name>` | Exactly one named retained source field, with `<name>` matching `[A-Za-z][A-Za-z0-9_]*`. The rule must declare `sources`. No nested access or arbitrary attribute lookup is allowed. |

All common and context paths are checked against the current
`NormalizedEvent` model at rule-load time. An unrecognized path or a context
field incompatible with a targeted category makes the rule invalid. A
syntactically valid `source_data` key cannot be guaranteed present at load
time; its absence in an event is handled as missing data. Access to
`source_data` is for explicitly source-scoped, source-specific conditions
only. Prefer normalized common or context fields whenever they represent the
same meaning. Retained `source_data` values are strings and receive no
implicit numeric, IP, or datetime conversion.

A rule is skipped, without a match, when the event's category or source is
outside its declared target set. For an eligible event, a nonexistent
`source_data` key is **missing**. A declared optional field whose value is
`None` is **absent**. Both yield `false` for `exists`, `true` for
`not_exists`, and `unknown` for every other operator, including
`not_equals` and `not_in`. An empty string is present, not `None`; it is
compared normally. A `not` node applied to an `unknown` child remains
`unknown`.

There is no type coercion during evaluation. Enum-backed `source`,
`category`, and `context.outcome` values compare using their declared string
values. Integer fields, including event/record/process IDs and ports, use
integer literals, not numeric strings or booleans. `timestamp` uses a
timezone-aware ISO 8601 literal, parsed and compared as an instant in UTC.
IP fields use validated IP literals rather than string or numeric ordering.
String operations are case-sensitive and do not perform path, hostname, or
Unicode normalization. An IP address and CIDR network of different families
do not match.

## Comparison operators

Rule loading checks each operator, field type, literal type, and list shape.
The supported set is closed:

| Operator | Valid fields and result when present |
| --- | --- |
| `equals`, `not_equals` | Strict scalar equality or inequality on strings, integers, enum values, aware datetimes, or IP addresses. |
| `contains` | String field contains the string literal as a substring. |
| `contains_any` | String field contains at least one substring from a non-empty list of string literals. |
| `starts_with`, `ends_with` | String field begins or ends with the string literal. |
| `in`, `not_in` | Strict membership or non-membership in a non-empty list of literals of the field's scalar type; not substring matching. |
| `exists`, `not_exists` | Field is present and non-`None`, or missing/`None`, respectively; no `value` key. |
| `greater_than`, `greater_or_equal`, `less_than`, `less_or_equal` | Integer comparison only on normalized integer fields. |
| `ip_in_cidr` | Validated normalized IP address belongs to a validated CIDR network literal of the same address family. |

For `source_data.*`, only string-compatible equality, membership, substring,
prefix/suffix, and existence operators are valid. Ordering and CIDR checks
require typed normalized fields. Null, mixed-type membership lists, empty
lists, booleans masquerading as integers, incompatible operators, malformed
IP/CIDR or datetime literals, and unsupported operators invalidate a rule at
load time. Regex is not part of the initial contract.

## Loading, failures, and determinism

The loader reads only explicitly configured files under `rules/windows/`, in
sorted repository-relative path order. It uses safe data parsing, rejects
YAML custom tags, aliases, merge keys, duplicate keys, path escapes, and
symlink targets outside the rule library, and never imports or executes rule
content. It validates the entire set before evaluation. A malformed file,
invalid rule, or duplicate `id` fails the **whole load** with a controlled
rule-validation error; it does not silently skip a rule or publish a partial
rule set. Duplicate IDs are invalid even when rule versions differ.

Evaluation accepts only validated rules and validated `NormalizedEvent`
objects. An unexpected runtime type mismatch is a controlled evaluation
error, not a coerced value, silent false result, or partial match. No rule
may use `eval`, `exec`, arbitrary Python expressions or imports, shell
commands, dynamic callbacks, executable code embedded in YAML, or plugin
discovery from rule files.

With the same validated rule set and event, evaluation returns the same
ordered result and condition trace. It does not depend on file discovery
order, wall-clock time, randomness, network access, external services, or
mutable state. Each eligible rule is evaluated once per event, yielding at
most one match for that pair; matches are ordered by rule `id`. The event's
own timestamp may be compared for equality but does not create a time
window or stateful correlation.

## DetectionMatch explanation

A `DetectionMatch` is evidence of **one rule matching one validated event**,
not an Alert. It contains at least:

- the stable rule `id`, `version`, and title used for evaluation;
- the matched `NormalizedEvent` or a lossless immutable in-memory snapshot of
  it, so the exact event can be identified even when `record_id` is absent;
- the root outcome (`true`) and an ordered condition-tree trace with stable
  node locations, such as `$.all[1]`;
- for each leaf, its field path, operator, expected literal when applicable,
  actual value when safe to expose, and `true`/`false`/`unknown` outcome;
- the matched branches and the reason for any missing or absent value.

The trace preserves how `all`, `any`, and `not` produced the root result. It
does not invent facts for absent fields. Values that may contain sensitive
source data can be redacted in an exported explanation while retaining the
path, operator, outcome, and a redaction marker; full events or raw XML are
not blindly logged or published. No match is emitted for a failed or unknown
root, and an evaluation error does not fabricate a match.

## Safe data and explicit non-goals

Rules, examples, and tests must follow [SECURITY.md](../SECURITY.md): use
synthetic or otherwise permitted public-safe data, fictional hosts and users,
reserved documentation domains/IP ranges, and no production telemetry,
credentials, secrets, personal data, employer/client identifiers, or
executable malicious payloads. Explanations must not turn untrusted
`source_data` into a public data leak.

v0.3.0 does **not** define or implement Alert generation or lifecycle,
severity/priority workflow, analyst triage, stateful aggregation,
time-window correlation, database persistence, streaming or Kafka, API or UI,
IOC enrichment, verdicts, escalation, arbitrary Python rules, or a Sigma
compatibility layer. It does not change the released v0.2.0 ingestion and
normalization contracts. Runtime Detection Engine implementation is a later
Issue and must follow this contract only after it is merged.
