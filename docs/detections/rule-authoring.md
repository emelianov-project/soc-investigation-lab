# Authoring Detection Rules

## Scope and prerequisites

The v0.3.0 Detection Engine is implemented on `main`; release preparation is
still pending. v0.1.0 and v0.2.0 are released. This guide describes the existing
data-only rule contract, not an Alert or investigation system. Read the
[architecture](../architecture/detection-engine.md) and
[merged contract](../detection-engine-scope.md) for design and boundaries.

Rules live recursively under [`rules/windows/`](../../rules/windows/), currently
in `account/`, `execution/`, `network/`, and `persistence/`. Use UTF-8 regular
files with lowercase `.yaml` or `.yml` extensions, one rule mapping per file.
The loader requires an explicit absolute library root. Do not use links,
external files, remote URLs, plugin directories, or executable rule content.

## Minimal rule

This complete synthetic example targets an image suffix. It is documentation,
not an additional committed library rule:

```yaml
id: example-process-image
version: 1
title: Example process image
description: Selects a synthetic process image for demonstration.
categories:
  - process
condition:
  field: context.image
  op: ends_with
  value: '\example.exe'
```

`C:\Lab\example.exe` matches; `C:\Lab\other.exe` does not. Use YAML single
quotes for Windows path fragments so backslashes remain literal.

| Top-level key | Authoring requirement |
| --- | --- |
| `id` | Stable lowercase slug made of lowercase letters/digits separated by single hyphens; unique across all files and versions. |
| `version` | Positive integer, starting at 1; not a string or boolean. |
| `title` | Concise nonblank human-readable name. |
| `description` | Nonblank statement of the observable behavior and its limitations, not a claim that every match is malicious. |
| `categories` | Non-empty unique list from `authentication`, `process`, `network`, `file`, `dns`. |
| `sources` | Optional unique non-empty list from `windows_security`, `sysmon`; mandatory if any condition references `source_data`. Omit rather than use `null` or an empty list. |
| `condition` | One leaf, `all`, `any`, or `not` tree; maximum depth 8 (root counts as 1), maximum 64 leaves. |

Extra keys are rejected. There is no severity, priority, Alert metadata, script,
callback, regex, aggregation, threshold, or time-window section.

Keep an ID when revising the same detection's criteria and increment its
version so evidence identifies the revision. Use a new ID for a genuinely
different behavior/identity. Do not keep multiple versions of the same ID as
separate files: duplicate IDs invalidate the whole library.

## Condition composition

A leaf is a `field`/`op`/`value` mapping. The minimal rule above is an example.
Existence checks omit `value`. The following are alternative `condition`
fragments for process rules, not complete rule files:

```yaml
condition:
  all:
    - field: context.image
      op: ends_with
      value: '\example.exe'
    - field: context.command_line
      op: contains
      value: ' DEMO_MARKER '
```

```yaml
condition:
  any:
    - field: context.image
      op: ends_with
      value: '\example.exe'
    - field: context.image
      op: ends_with
      value: '\other-example.exe'
```

```yaml
condition:
  not:
    field: context.command_line
    op: exists
```

`all` and `any` require non-empty ordered lists; `not` takes exactly one child.
Every child is evaluated in order, without short-circuiting, and appears in
the trace. Keep each rule focused on one observable behavior and choose narrow,
explainable fields rather than a large collection of unrelated indicators.

## Available fields

Common fields are `source`, `provider`, `event_id`, `channel`, `timestamp`,
`computer`, `record_id`, and `category`. `event_id` and `record_id` are integers;
`timestamp` is timezone-aware; the other common fields have string semantics.
`record_id` is optional.

Use `context.<field>` for the following allowlisted fields only. Unmarked fields
are strings; `(int)` and `(IP)` identify typed integers and addresses:

| Rule category | Allowed context fields |
| --- | --- |
| `authentication` | `outcome`, `user`, `domain`, `logon_type` (int), `source_ip` (IP), `source_port` (int), `workstation` |
| `process` | `image`, `process_id` (int), `command_line`, `parent_process_id` (int), `parent_image`, `user` |
| `network` | `source_ip` (IP), `source_port` (int), `destination_ip` (IP), `destination_port` (int), `protocol`, `process_id` (int), `process_image` |
| `file` | `target_path`, `process_id` (int), `process_image` |
| `dns` | `query_name`, `query_status`, `query_results`, `process_id` (int), `process_image` |

Not every declared field is required in the event. For example, process
`image` is required but `command_line` is optional. See the
[normalized contracts](../../backend/app/models/normalized_event.py) for required
versus optional context fields.

No dotted traversal beyond one context field is supported. Paths such as
`context.image.name`, `context.__class__`, `context.image[0]`, and wildcards are
invalid; an unrecognized field is not treated as absent.

### Multi-category rules

Every leaf must be valid for **every** declared category, with the same semantic
type. This fragment is valid for a rule targeting both network and file events:

```yaml
categories: [network, file]
condition:
  field: context.process_id
  op: greater_than
  value: 0
```

The following is invalid at load time because DNS has `process_image`, not
`image`. Putting it under `any` would not make it valid:

```yaml
categories: [process, dns]
condition:
  field: context.image
  op: ends_with
  value: '\example.exe'
```

Split rules when category contracts differ instead of relying on runtime
absence or target filtering to hide an invalid declared field.

### Source-specific retained text

Use typed context fields for shared semantics. Only use `source_data.<name>`
when retained source-specific text is necessary, and declare `sources`:

```yaml
sources: [sysmon]
categories: [network]
condition:
  field: source_data.Initiated
  op: equals
  value: 'true'
```

This is a fragment for a Sysmon-scoped rule. `Initiated` is retained text, not a
boolean. Quote it. Names must be one ASCII segment beginning with a letter and
continuing with letters, digits, or underscores. Missing keys are MISSING;
present values remain strings. Numeric ordering on `source_data.ProcessId` or
CIDR membership on retained address-looking text is invalid. Do not use retained
fields as a fallback to raw XML or bypass source/category validation.

## Operator reference

All operators are case-sensitive where strings are involved. There is no path,
hostname, Unicode, or case normalization and no implicit number conversion.
`"1"` and `True` cannot be integer `1`. Enum-backed fields use declared string
values such as `sysmon`, `process`, and `failure`.

| Operator | Expected `value` | Compatible field / authoring meaning |
| --- | --- | --- |
| `equals` | One compatible string/integer literal | Exact typed equality; typed IP/time fields use parseable string literals. |
| `not_equals` | Same as `equals` | Typed inequality, not a test for missing data. |
| `contains` | String | String contains this exact substring. |
| `contains_any` | Non-empty string list | String contains at least one listed substring. |
| `starts_with` | String | Exact string prefix. |
| `ends_with` | String | Exact string suffix. |
| `in` | Non-empty homogeneous compatible scalar list | String/integer/IP/time membership. Every item is validated. |
| `not_in` | Same as `in` | Typed non-membership, not a test for missing data. |
| `exists` | Omit entirely | Field is present and not `None`. |
| `not_exists` | Omit entirely | Declared field is `None` or retained key is missing. |
| `greater_than` | Integer | Integer field is greater than operand. |
| `greater_or_equal` | Integer | Integer field is greater than or equal to operand. |
| `less_than` | Integer | Integer field is less than operand. |
| `less_or_equal` | Integer | Integer field is less than or equal to operand. |
| `ip_in_cidr` | CIDR string, for example `'192.0.2.0/24'` | Typed normalized IP belongs to a valid network. |

IP comparisons parse literals as IPv4/IPv6 addresses, not raw strings. CIDR
network literals must be valid under strict `ipaddress.ip_network` parsing;
IPv4 against IPv6 (or the reverse) returns FALSE. `contains` on an IP is invalid.

For timestamp equality or membership, quote timezone-aware ISO-8601 operands,
for example `'2026-01-01T00:00:00Z'`. They compare as UTC instants. Naive strings
and timestamp numeric ordering are invalid. Do not compare timestamps
lexicographically or invent a time-window rule.

## Missing data and three-valued logic

For a valid condition, a missing `source_data` key or an optional field equal to
`None` gives FALSE for `exists`, TRUE for `not_exists`, and UNKNOWN for every
other operator. This includes `not_equals` and `not_in`; absence is not evidence
of a successful negative comparison. Empty strings and integer zero are present.

`all` is FALSE if any child is FALSE, TRUE if every child is TRUE, and otherwise
UNKNOWN. `any` is TRUE if any child is TRUE, FALSE if every child is FALSE, and
otherwise UNKNOWN. `not` flips TRUE/FALSE and preserves UNKNOWN.

For a matching image but absent optional `context.command_line`, a command-line
`contains` condition is UNKNOWN. An `all` of those two conditions is UNKNOWN
and creates no `DetectionMatch`. Invalid field/operator combinations fail
validation; they are not converted into UNKNOWN.

## Validation and safe failures

`load_detection_rules(absolute_root)` performs safe parsing, `DetectionRule`
structural validation, shared semantic validation, and collection-wide duplicate
checks. It returns only after the complete library passes. Files load in sorted
relative POSIX-path order; evaluation and matches are ordered by rule ID.

These are examples of load-time errors, not runtime non-matches:

- `context.nonexistent_field`, or a context field unavailable in any target category.
- `event_id` with `contains`, a string field with `greater_than`, or a non-IP
  field with `ip_in_cidr`.
- Quoted numeric operands for integers, booleans masquerading as integers,
  invalid IP/CIDR strings, naive/invalid timestamps, or a bad membership item.
- `source_data` conditions without `sources`, malformed condition trees,
  unknown operators, extra keys, or duplicate IDs (even across versions).

The loader rejects duplicate YAML keys, custom/Python tags, anchors, aliases,
merge keys, multiple documents, empty/scalar/list documents, invalid UTF-8,
path escapes, and links below the root. Do not use `eval`, `exec`, embedded
code, callbacks, dynamic imports, plugins, or shell execution. YAML is data only.

Loading errors derive from `DetectionRuleLoadError`: `DetectionRuleFileError`
provides a safe relative path/category and `DuplicateDetectionRuleIdError`
identifies the ID and conflicting paths. Invalid structural or semantic rules
are reported as `invalid_rule` without dumping file contents. No partial library
is returned. Runtime defense remains for direct Python callers and invalid or
mutated objects; it raises `DetectionEvaluationError` subclasses rather than
returning partial traces or matches. See the
[failure reference](../architecture/detection-engine.md#controlled-failures).

## Test a rule without executing its content

Use synthetic `NormalizedEvent` inputs and the real `load_detection_rules` and
`evaluate_event` APIs. For direct Python rule construction, validate with
`DetectionRule` and `validate_detection_rule_semantics` first. The architecture's
[Python example](../architecture/detection-engine.md#python-integration-example)
shows the existing XML normalization → real library → match pipeline; no CLI
or network service is required.

For the committed `powershell-encoded-command` rule, keep image
`C:\Lab\powershell.exe` and vary only this synthetic text:

| Command-line input | Expected rule result |
| --- | --- |
| `powershell.exe -EncodedCommand BENIGN_PLACEHOLDER` | TRUE; one match for that rule with both image alternatives and command-line evidence. |
| `powershell.exe -NoProfile` | FALSE; no match. |
| `None` (optional field absent) | UNKNOWN; no match. |

The marker is deliberately not an encoded payload. Never run these strings as
commands or introduce malicious Base64. Also test case changes, near misses,
wrong category/source, missing optional values, and repeatability. A negative
test should fail the intended condition, not merely accidentally target the
wrong category. Assert rule identity/version, root outcome, ordered trace
locations, expected/actual evidence, and absence markers as appropriate.

Use [`backend/tests/detection/test_rule_library.py`](../../backend/tests/detection/test_rule_library.py)
for the actual six-rule positive/negative examples;
[`test_loader.py`](../../backend/tests/detection/test_loader.py) for temporary
YAML validation and failure cases; and
[`tests/integration/test_detection_pipeline.py`](../../tests/integration/test_detection_pipeline.py)
for XML-to-match behavior. New library behavior should have focused positive,
negative, optional-data, and integration coverage as applicable. Do not weaken
rules or tests to hide UNKNOWN or a controlled failure.

Run the [repository quality gate](../testing.md#run-the-repository-quality-gate).
Tests are deterministic and offline; use temporary synthetic rule trees for
loader edge cases, not production telemetry or unrelated permanent rule files.

## Safe-data and interpretation checklist

- Use fictional hosts/users, `example.com`, and reserved documentation IP
  ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Do not copy employer/client/production telemetry, credentials, personal data,
  internal URLs, secrets, or executable malware into examples or evidence.
- Review the [security policy](../../SECURITY.md) before publishing traces.
  Actual values are retained in memory; automatic export redaction is not
  provided by the engine.
- Explain false positives and narrow matching assumptions. A match is not
  proof of compromise, persistence, DNS tunneling, or brute force.
- Keep output at `DetectionMatch`. Alert lifecycle, analyst triage,
  investigation, enrichment, severity/priority, verdicts, persistence, API,
  and UI remain planned. Stateful/cross-event correlation and general Sigma
  support are not implemented.
