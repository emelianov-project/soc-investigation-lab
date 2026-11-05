# v0.4.0 — Alert Management contract

## Status and boundary

This is the authoritative contract for the remaining v0.4.0 Alert Management
implementation Issues. **v0.4.0 is planned; this document does not implement
Alert Management.** v0.3.0 — Detection Engine is released and ends at a validated
`DetectionMatch`. The v0.4.0 boundary is:

```text
Windows Event XML → RawWindowsEvent → Parser Registry → Source Normalizer
→ NormalizedEvent → Detection Engine → DetectionMatch
                                      v0.4.0 begins here ↓
DetectionMatch → Alert creation → Alert lifecycle and severity/priority handling
→ in-process analyst-facing alert queue
                                      Investigation is outside this boundary
```

An Alert is an analyst-facing unit of work created from **one existing TRUE
`DetectionMatch`**: one rule matched one `NormalizedEvent`. Alert Management
must not rerun a rule, reevaluate a `ConditionTrace`, reinterpret FALSE/UNKNOWN,
or change the source match or event. A match is evidence, not an Alert or proof
of maliciousness. See the [Detection Engine architecture](architecture/detection-engine.md)
and the [released rule contract](detection-engine-scope.md).

## Typed Alert identity and evidence

The minimal logical Alert value has:

| Field | Contract |
| --- | --- |
| `alert_id` | Stable, caller-supplied, non-empty ASCII lowercase slug: `[a-z0-9]+(?:-[a-z0-9]+)*`, at most 128 characters. Unique within an accepted collection; never derived from sensitive event text. |
| `source_match` | An owned, lossless, detached, read-only snapshot of the validated `DetectionMatch`, including rule ID/version/title, the typed normalized event, root outcome, and complete ordered trace. |
| `created_at` | Explicit timezone-aware creation instant, normalized to UTC; never changes. |
| `state` | One of `new`, `acknowledged`, `closed`; initially `new`. |
| `state_changed_at` | UTC instant of the most recent actual lifecycle change; initially `created_at`. |
| `severity` | One of `unassigned`, `informational`, `low`, `medium`, `high`, `critical`; initially `unassigned`. |
| `priority` | One of `low`, `normal`, `high`, `urgent`; initially `normal`. |
| `updated_at` | UTC instant of the most recent actual state, severity, or priority change; initially `created_at`. |

`source_match` is copied once at creation into Alert-owned evidence, rather
than retaining a caller-owned mutable reference. The snapshot must preserve
the exact validated match values and typed semantics, including the entire
`NormalizedEvent` and `ConditionTrace`, while preventing changes to the source
or to the Alert's internal evidence through an exposed mutable alias. A
read-only view or defensive copy may be exposed to callers. The Alert need not
copy `rule_id`, `rule_version`, or event fields into separate mutable columns:
those are derived read-only from `source_match` for traceability. The Alert's
identity, timestamps, state, severity, and priority are Alert-owned data, not
fields added to `DetectionRule`. This choice preserves why the Alert exists
even if the caller later changes its original in-memory objects, without
silently replacing detection evidence with a summary.

The snapshot may contain source-specific or personal-looking values. It is
in-memory evidence, **not** automatically safe to log or export. Any later
presentation must apply the repository's [security policy](../SECURITY.md) and
redact sensitive values without changing the underlying match outcome.

## Deterministic creation

Conceptually, `create_alert(match, alert_id, created_at, *, severity=unassigned,
priority=normal) -> Alert` is a pure domain operation. All inputs are explicit;
the match must be a validated TRUE `DetectionMatch` whose root trace is TRUE.
Creation checks the ID grammar, enum values, timestamp, and evidence contract,
then produces a new validated Alert with a detached evidence snapshot and the
defaults above. It does not read the wall clock, generate a UUID, use
randomness, inspect environment state, or look up rule files. A caller may
obtain an ID and clock value through a separate controlled boundary; those
dependencies must be passed into this operation, not hidden inside it.

The same match, ID, timestamp, severity, and priority produce equal Alert
values on repeated calls. Creation itself neither registers nor deduplicates
Alerts. A different ID for the same match is a distinct Alert; this contract
does not perform cross-event or cross-alert deduplication. When a managed
collection is supplied to queue operations, any repeated `alert_id` is a
controlled duplicate-ID error, even if the two Alert values are otherwise
equal. A reused ID with different evidence is never silently accepted.

## Severity and priority are different

Severity expresses the assigned security significance of the detection
context. Its ordered assigned levels are `informational < low < medium < high
< critical`. `unassigned` is a distinct *lack of assessment*, not a lower
security significance or a maliciousness verdict. Creation defaults to
`unassigned` because the v0.3.0 rule and match contracts do not assign
severity. The queue gives it an explicit final tie rank after informational;
that sort placement is operational only, not a risk assertion.

Priority expresses operational handling urgency, independently of severity.
Its order is `low < normal < high < urgent`, with explicit creation default
`normal`. A high-severity condition does not automatically have urgent
priority; future policy may consider context outside this milestone. The
v0.4.0 contract does not perform enrichment or asset-criticality lookup and
does not derive either value from `DetectionRule`. Neither value proves that
activity is malicious or constitutes an analyst verdict.

While an Alert is active, explicit `set_severity(alert, value, changed_at)`
and `set_priority(alert, value, changed_at)` operations may assign or revise
these values. They return a new validated Alert, retain the evidence and
lifecycle timestamps, and update only the selected value and `updated_at`.
Assigning the existing value is a validated no-op that returns the unchanged
value and does not advance a timestamp. Closed Alerts cannot be reassessed in
this contract. No implicit severity-to-priority mapping exists.

## Lifecycle and time

The deliberately small lifecycle is:

```text
new → acknowledged → closed
```

`new` means awaiting queue review; `acknowledged` means the item has been
taken up for alert handling, **not** that an Investigation has begun; `closed`
means its Alert Management queue work ended, **not** False Positive, True
Positive, or any other verdict. An `in_progress` state is omitted because it
would duplicate the later Investigation workflow without a distinct v0.4.0
meaning. `closed` is terminal.

Only `new → acknowledged` and `acknowledged → closed` change state. Direct
`new → closed`, backwards transitions, reopening, and changes from `closed`
to a different state are forbidden. Domain operations such as `acknowledge_alert(alert, at)` and
`close_alert(alert, at)` must enforce the transition graph; arbitrary
`alert.state = ...` assignment is forbidden. Each successful transition
returns a **new** validated Alert value, leaving the input and owned evidence
unchanged. This value-oriented design supports a later persistence boundary
without designing one now.

All domain timestamps are timezone-aware `datetime` values. Naive, invalid,
or string-coerced timestamps are rejected. Creation and change operations
accept their times explicitly, compare them as UTC instants, and normalize
stored values to UTC. A change time must be at least the Alert's `updated_at`;
`created_at` never changes. A real state transition updates both
`state_changed_at` and `updated_at`. An explicit policy change updates
`updated_at` only. A requested transition to the current state is an
idempotent no-op after timestamp validation; it returns the unchanged Alert
and creates no new history or clock value. No core operation calls
`datetime.now()` or reads an implicit clock.

## In-process analyst-facing queue

Conceptually, `list_alerts(alerts, *, states=None, severities=None,
priorities=None) -> tuple[Alert, ...]` takes a finite collection of validated
Alert values. It snapshots and validates the *entire* input, including closed
Alerts and IDs, before filtering or returning anything. Duplicate IDs or
invalid elements fail the whole call. It never mutates the collection or
Alert values and is not a database, API, frontend, or durable message queue.

The default state filter selects active `new` and `acknowledged` Alerts;
`closed` Alerts are visible only when explicitly requested. Each supplied
filter is a non-empty set of exact enum values: OR within one filter and AND
across state, severity, and priority. `None` means the default active-state
filter for `states`, and no restriction for the other two filters. Passing
all three states explicitly includes closed Alerts. Empty or malformed filter
sets are errors, not silently broadened queries. An empty input or a valid
filter with no matches returns an empty tuple.

Results have this total, stable order, independent of input enumeration:

1. Priority descending: `urgent`, `high`, `normal`, `low`.
2. Severity descending: `critical`, `high`, `medium`, `low`, `informational`,
   then `unassigned` as a non-assessment tie rank.
3. `created_at` ascending as a UTC instant (older first).
4. `alert_id` ascending by its ASCII lexical value.

Distinct IDs guarantee a final tie-breaker. Severity does not set priority;
the queue's separate sort keys are an explicit presentation policy only.

## Controlled failures and atomicity

Implementation should expose a small domain-specific error family rather than
leaking raw `ValueError`, `TypeError`, or validation traces to callers:

| Failure | Required behavior |
| --- | --- |
| Invalid Alert or malformed ID | Reject before returning a value; do not coerce identifiers or incomplete evidence. |
| Invalid, naive, or out-of-order timestamp | Reject the creation or change; no hidden fallback clock. |
| Invalid severity or priority | Reject construction, change, or filter; do not coerce arbitrary strings or infer from a rule. |
| Forbidden lifecycle transition or change to a closed Alert | Reject with an explicit transition error; leave the input unchanged. |
| Duplicate `alert_id` anywhere in a supplied collection | Reject the whole queue operation before filtering or sorting. |
| Malformed collection or filter | Reject the whole call; do not silently skip Alerts or return a partial tuple. |

Public errors should identify the category and safe ID or field name where
useful, not dump the `DetectionMatch`, event, trace actual values, or private
source data. Creation, transition, policy update, and queue operations are
atomic: a failure never mutates input Alert state or yields a partially
updated collection.

## Testing and safe data requirements for later implementation Issues

Use synthetic validated matches and events, fictional users/hosts, reserved
documentation IP ranges, and `example.com` domains. Cover ID validation,
evidence isolation and traceability, repeat creation, explicit clock input,
timezone normalization, all lifecycle edges and no-ops, severity/priority
independence, closed-state restrictions, every queue filter and tie-breaker,
duplicates before filtering, and whole-operation failures. Tests must prove
that changing the caller's original match/event cannot change Alert evidence.
No test should require a database, service, network access, production logs,
secrets, or real personal information.

## Explicit non-goals

v0.4.0 stops at the in-process Alert Management boundary. It does **not**
implement Investigation, evidence collection workflow, analyst notes,
timelines, related-event discovery, IOC enrichment, MITRE ATT&CK runtime
enrichment, False Positive/True Positive verdicts, escalation, case
management, cross-event/time-window detection correlation, database
persistence, ORM, migrations, an HTTP/backend API, authentication or
authorization, a web UI, notification delivery, Kafka/streaming, or live
telemetry collection. Those concepts remain future work. This contract also
does not add Alert fields to `DetectionRule` or alter the released v0.3.0
Detection Engine and match semantics.
