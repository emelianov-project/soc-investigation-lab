# Detection Engine Architecture

## Status and boundary

v0.1.0 — Project Foundation and v0.2.0 — Event Processing are released.
v0.3.0 — Detection Engine is released. This document describes that released
implementation. The [merged scope contract](../detection-engine-scope.md) defines its
boundary; the [authoring guide](../detections/rule-authoring.md) explains how to
write rules for it.

The engine is an offline, stateless Python component. It consumes one validated
`NormalizedEvent` and a collection of validated `DetectionRule` objects and
returns `tuple[DetectionMatch, ...]`. A match explains one rule matching one
event. It is not an Alert, a maliciousness verdict, or an analyst decision.

The implemented path is:

Windows Event XML → `RawWindowsEvent` → parser registry → source normalizer →
`NormalizedEvent` → Detection Engine → `DetectionMatch`.

The [event-processing architecture](event-processing.md) describes the v0.2.0
input layer, whose own boundary remains `NormalizedEvent`. Detection is the
separate v0.3.0 layer described here.

```mermaid
flowchart LR
    Y[Controlled YAML library] --> L[Safe loading and validation]
    L --> R[DetectionRule collection]
    R --> F[Category and source applicability]
    E[NormalizedEvent] --> F
    F --> V[evaluate_condition]
    V --> T[Complete ConditionTrace]
    T --> M[TRUE-only DetectionMatch tuple]
    M -. planned, outside v0.3.0 .-> A[Alert and analyst workflow]
```

## Components and public APIs

| Component | Responsibility |
| --- | --- |
| [`models/detection.py`](../../backend/app/models/detection.py) | Data contracts: `DetectionRule`, `DetectionOperator`, `LeafCondition`, `AllCondition`, `AnyCondition`, `NotCondition`, `ConditionNode`, `ConditionOutcome`, `ConditionTrace`, and `DetectionMatch`; no loading or evaluation. |
| [`detection/semantics.py`](../../backend/app/detection/semantics.py) | Shared field/type maps, category compatibility, operator compatibility, and typed literal validation. `validate_detection_rule_semantics(rule)` checks a structurally validated rule without an event or filesystem access. |
| [`detection/loader.py`](../../backend/app/detection/loader.py) | `load_detection_rules(rule_root: Path) -> tuple[DetectionRule, ...]`: safe recursive discovery, YAML parsing, structural and semantic validation, duplicate-ID protection, whole-load failure. |
| [`detection/evaluator.py`](../../backend/app/detection/evaluator.py) | `resolve_event_field(event, field_path) -> ResolvedField` and `evaluate_condition(event, condition) -> ConditionTrace`: explicit resolution, presence states, typed comparisons, three-valued logic, complete ordered traces. |
| [`detection/engine.py`](../../backend/app/detection/engine.py) | `evaluate_event(event, rules) -> tuple[DetectionMatch, ...]`: collection checks, applicability filtering, rule-ID ordering, condition evaluation, TRUE-only match construction. |
| [`detection/errors.py`](../../backend/app/detection/errors.py) | Controlled loading, evaluation, and orchestration failures. |

Public application APIs are exported by
[`app.detection`](../../backend/app/detection/__init__.py). Models remain under
`app.models`; YAML/file handling and evaluation do not belong in model classes.

## Rule loading and validation

The configured library is [`rules/windows/`](../../rules/windows/). Supply an
explicit **absolute directory** to `load_detection_rules`; the loader resolves
it as the trust boundary. It recursively discovers regular files with lowercase
`.yaml` or `.yml` extensions and ignores unrelated regular-file extensions.
Files are processed in sorted root-relative POSIX path order, independent of
directory enumeration order or the process working directory. An empty valid
library returns `()`.

Each accepted file follows this sequence:

1. Check path containment and read UTF-8 without replacement decoding.
2. Parse exactly one non-empty top-level YAML mapping safely.
3. Validate its structure through `DetectionRule`.
4. Validate its field/type/literal semantics for every declared target category.
5. Check its ID against the other loaded rules.

Only after the whole library succeeds is the tuple returned. No malformed rule
is skipped, and no partially valid tuple is returned. Duplicate IDs fail even
when the files declare different versions.

Structural model validation alone does not prove a rule is evaluable. The
shared semantic layer now rejects unknown context fields, fields unavailable
in any declared category, cross-category type incompatibility, invalid
operator/type pairings, and invalid typed operands **during loading**. It also
enforces source-scoped `source_data` use. For example, `context.nonexistent_field`
and `event_id` with `contains` are load-time `invalid_rule` failures.

Membership validation checks every operand, including those after an otherwise
matching value. Integers must be integer literals, IP literals must parse as
addresses, timestamp literals must be timezone-aware, and CIDR literals must
be valid networks. Nested leaves are checked even under a logical branch that
could be decisive at runtime.

### YAML and filesystem safety

PyYAML's `SafeLoader` is augmented with explicit syntax checks. The loader rejects
aliases, anchors, explicit/custom tags (including Python/object tags), merge
keys, duplicate or non-string mapping keys, malformed YAML, multiple documents,
empty documents, and scalar/list top levels. Rules are data, never executable
Python objects, callbacks, plugins, expressions, or shell commands.

Discovered paths must remain inside the resolved root. Links below that root
are rejected, including in-root symlinks and Windows reparse points; linked
directories are not followed. Parent escapes, non-regular YAML files, read
failures, and invalid UTF-8 fail explicitly. Keep the controlled library stable
during loading. These checks are not a general-purpose operating-system sandbox
for hostile concurrent filesystem changes.

## DetectionRule contract

| Field | Contract |
| --- | --- |
| `id` | Stable lowercase slug, for example `powershell-encoded-command`; unique across the library regardless of version. |
| `version` | Positive strict integer, not a boolean or numeric string. |
| `title`, `description` | Required strings containing non-whitespace text. |
| `categories` | Non-empty list of unique `EventCategory` values: `authentication`, `process`, `network`, `file`, `dns`. |
| `sources` | Omitted, or a non-empty unique list of `windows_security` / `sysmon`; required for any `source_data` condition. Explicit `null` is invalid. |
| `condition` | Exactly one bounded condition tree. |

Extra fields are forbidden, including severity, priority, and executable hooks.
The maximum condition depth is eight nodes, counting the root as depth one;
the maximum number of leaves is 64.

A leaf has `field`, `op`, and an operator-appropriate `value`. `exists` and
`not_exists` must omit `value`. An `all` or `any` node contains a non-empty
ordered child list. A `not` node contains exactly one condition. Mixed node
shapes and unrecognized operators are invalid.

## Field resolution and shared types

Only these common fields are resolvable:

| Semantic type | Common fields |
| --- | --- |
| String | `source`, `provider`, `channel`, `computer`, `category` |
| Integer | `event_id`, optional `record_id` |
| Timezone-aware timestamp | `timestamp` |

`EventSource`, `EventCategory`, and `AuthenticationOutcome` are compared using
their declared string values, not enum object identity or incidental Python
enum/string equality.

Context paths take the form `context.<field>`. This is the complete field map;
all unmarked fields below are strings, `(int)` means integer, and `(IP)` means
a typed IPv4/IPv6 address:

| Category | Supported context fields |
| --- | --- |
| `authentication` | `outcome`, `user`, `domain`, `logon_type` (int), `source_ip` (IP), `source_port` (int), `workstation` |
| `process` | `image`, `process_id` (int), `command_line`, `parent_process_id` (int), `parent_image`, `user` |
| `network` | `source_ip` (IP), `source_port` (int), `destination_ip` (IP), `destination_port` (int), `protocol`, `process_id` (int), `process_image` |
| `file` | `target_path`, `process_id` (int), `process_image` |
| `dns` | `query_name`, `query_status`, `query_results`, `process_id` (int), `process_image` |

Every leaf must make sense for **every** category in the rule. A rule targeting
`network` and `file` can use `context.process_id`; a rule targeting `process`
and `dns` cannot use `context.image`, even inside `any`. Runtime targeting does
not excuse an invalid declared contract.

`source_data.<name>` accesses one retained string key. The name is a single
ASCII segment starting with a letter, followed by letters, digits, or
underscores. It is not recursive traversal. Its value stays text: `"42"` is not
converted to an integer, and address/timestamp-looking strings are not promoted
to typed IPs or timestamps. Rules using it must declare `sources` explicitly.

There is no raw-XML fallback, wildcard, index, method call, arbitrary attribute
access, or deeper dotted path. Invalid paths are controlled errors, not missing
data. Runtime resolution uses the allowlist and the actual category's typed
context.

### Presence and absence

`ResolvedField` retains `path`, `field_type`, `presence`, and `value`.
`FieldPresence` distinguishes:

| State | Meaning | `exists` | `not_exists` | Other compatible comparisons |
| --- | --- | --- | --- | --- |
| `PRESENT` | Declared value is not `None`, or a retained key exists | TRUE | FALSE | Typed comparison |
| `MISSING` | Valid `source_data` key is not present | FALSE | TRUE | UNKNOWN |
| `ABSENT` | Declared optional field is `None` | FALSE | TRUE | UNKNOWN |

Empty strings and zero are present. Unknown is `ConditionOutcome.UNKNOWN`,
not a hidden Python `None` truth value. In particular, absent `command_line`
with `not_equals` or `not_in` is UNKNOWN, never a positive detection. Invalid
operator/type combinations still fail even if the actual value is absent.

## Operators and typed operands

The closed set contains exactly these 15 operators:

| Operator | Actual field type / operand | Meaning when present |
| --- | --- | --- |
| `equals` | String or integer scalar; IP or timestamp string literal appropriate to the typed field | Typed equality |
| `not_equals` | Same as `equals` | Typed inequality |
| `contains` | String / string | Exact substring containment |
| `contains_any` | String / non-empty string list | At least one substring is contained |
| `starts_with` | String / string | Exact prefix |
| `ends_with` | String / string | Exact suffix |
| `in` | String, integer, IP, or timestamp / non-empty compatible scalar list | Typed membership |
| `not_in` | Same as `in` | Typed non-membership |
| `exists` | Any supported field / no value | PRESENT |
| `not_exists` | Any supported field / no value | MISSING or ABSENT |
| `greater_than` | Integer / integer | Strict greater-than |
| `greater_or_equal` | Integer / integer | Greater-than or equal |
| `less_than` | Integer / integer | Strict less-than |
| `less_or_equal` | Integer / integer | Less-than or equal |
| `ip_in_cidr` | Typed IP / CIDR string | Address belongs to network |

String operations are case-sensitive and preserve exact Unicode text. There
is no case folding, path/hostname normalization, Unicode normalization, or
regex. `PowerShell.exe` does not equal `powershell.exe`.

No general implicit coercion is performed: `"1"` and `True` cannot stand in for
integer `1`. Numeric ordering applies only to normalized integer fields, not
timestamps or numeric-looking `source_data`. IP equality/membership parse
expected strings into typed addresses. CIDR uses `ipaddress.ip_network` with
strict network validation; cross-family IPv4/IPv6 comparisons return false.

Timestamp equality/membership parse quoted timezone-aware ISO-8601 strings and
compare instants in UTC. Naive/invalid timestamps fail; comparison is not
lexicographic, and timestamp ordering operators are not supported. Quote YAML
timestamp operands so the parser supplies literal text for semantic validation.

## Logical evaluation, targeting, and determinism

| Node | TRUE | FALSE | UNKNOWN |
| --- | --- | --- | --- |
| `all` | Every child is TRUE | At least one child is FALSE | Otherwise |
| `any` | At least one child is TRUE | Every child is FALSE | Otherwise |
| `not` | Child is FALSE | Child is TRUE | Child is UNKNOWN |

There is **no short-circuiting**: every child is evaluated in declared order,
even after a decisive outcome, to preserve complete explanations. An invalid
later child still raises an error; it is not hidden by an earlier result.

`evaluate_event` checks the collection and duplicate IDs before evaluation,
including rules that will be inapplicable. It evaluates rules in ascending ID
order. Category membership and optional source membership are checked before
condition evaluation. Inapplicable rules are skipped without evaluating their
conditions. An eligible rule produces at most one match for the event, and only
when its root outcome is TRUE; FALSE and UNKNOWN produce no match. No matches,
or an empty collection, produce `()`.

Loader order is relative **file-path** order; engine/match order is **rule-ID**
order. These are deliberately different. Identical validated inputs produce
identical ordered results and traces. Evaluation does not depend on wall-clock
time, randomness, network services, or cross-event mutable state. Inputs are
not mutated. A later error aborts the call without returning earlier matches.

## DetectionMatch and explainability

`DetectionMatch` contains `rule_id`, `rule_version`, `rule_title`, `event`,
`root_outcome`, and `trace`. Both root outcomes must be TRUE and the trace starts
at `$`. The engine retains the supplied event object; this is not a frozen
snapshot or a storage/export format. Callers must keep it stable.

`ConditionTrace` records `location`, `kind`, `outcome`, and ordered `children`.
Leaf evidence includes `field`, `op`, `expected` (except existence operators),
and the present `actual` value or `absence="missing"` / `absence="absent"`.
Locations are stable: `$`, `$.all[0]`, `$.all[0].any[0]`, `$.not`, and so on.

For the committed `powershell-encoded-command` rule, a synthetic process with
image `C:\Lab\powershell.exe` and command line
`powershell.exe -EncodedCommand BENIGN_PLACEHOLDER` produces this compact trace
view (the command is inert test text, not something to execute):

| Location | Kind / comparison | Outcome |
| --- | --- | --- |
| `$` | `all` | TRUE |
| `$.all[0]` | `any` | TRUE |
| `$.all[0].any[0]` | `context.image ends_with '\powershell.exe'`; actual `C:\Lab\powershell.exe` | TRUE |
| `$.all[0].any[1]` | `context.image ends_with '\pwsh.exe'`; same actual | FALSE |
| `$.all[1]` | `context.command_line contains_any [' -EncodedCommand ', ' -encodedcommand ', ' -enc ']`; actual command above | TRUE |

Changing only the command to `powershell.exe -NoProfile` makes the last leaf and
root FALSE; removing the optional command makes that leaf and root UNKNOWN.
Neither produces a match. Both suffix children remain in the trace.

In-memory traces contain actual values. The model supports `redacted` and
`redaction_marker`, but the engine does not automatically redact evidence.
Before publishing/exporting any event or trace, apply the
[safe-data policy](../../SECURITY.md); do not dump full production telemetry.

## Controlled failures

| Error family | Meaning |
| --- | --- |
| `DetectionRuleLoadError` | Base for whole-library loading failures. |
| `DetectionRuleFileError` | Safe relative `path` and `category`: unsafe paths/YAML, read or UTF-8 failure, invalid document, or `invalid_rule` after structural/semantic validation. |
| `DuplicateDetectionRuleIdError` | Duplicate `rule_id`, `first_path`, and `duplicate_path`, irrespective of versions. |
| `DetectionEvaluationError` | Controlled evaluation failure; no partial trace or match tuple. |
| `InvalidDetectionFieldError` | Field not allowed for the actual event/category. |
| `IncompatibleDetectionConditionError` | Field/operator/literal incompatibility with a reason category. |
| `DetectionEngineError` | Invalid event/collection/item, duplicate collection IDs, or invalid match construction. |

The first two specific load errors derive from `DetectionRuleLoadError`;
field, condition, and engine errors derive from `DetectionEvaluationError`.
Loader semantic failures are translated into file-aware `invalid_rule` errors,
not exposed as raw Pydantic/YAML exceptions or full rule contents. Evaluation
errors use field/operator/reason context without dumping events or operands.

The evaluator retains defensive checks for direct Python callers, mutated
objects, or bypassed validation. Those runtime checks do not defer normal YAML
semantic validation until an event arrives. Python callers constructing rules
directly should perform structural and `validate_detection_rule_semantics`
validation before giving them to the engine.

## Initial Windows rule library

Exactly six version-1 rules are committed. Each omits `sources`, so applicability
is category-based across the supported sources. These are transparent educational
triage signals, not enterprise coverage metrics or proof of maliciousness.

| ID / file under `rules/windows/` | Title | Category | Match criterion |
| --- | --- | --- | --- |
| [`failed-remote-authentication`](../../rules/windows/account/failed-remote-authentication.yaml) (`account/failed-remote-authentication.yaml`) | Failed network or remote-interactive authentication | `authentication` | Failure outcome and logon type 3 or 10; one event, not brute-force counting. |
| [`certutil-suspicious-arguments`](../../rules/windows/execution/certutil-suspicious-arguments.yaml) (`execution/certutil-suspicious-arguments.yaml`) | Certutil transfer or decode argument | `process` | Image suffix `\certutil.exe` and command containing ` -urlcache ` or ` -decode `; legitimate administration can match. |
| [`powershell-encoded-command`](../../rules/windows/execution/powershell-encoded-command.yaml) (`execution/powershell-encoded-command.yaml`) | PowerShell encoded-command argument | `process` | Image suffix `\powershell.exe` or `\pwsh.exe` and one of ` -EncodedCommand `, ` -encodedcommand `, ` -enc `; no payload decoding. |
| [`dns-suspicious-query-marker`](../../rules/windows/network/dns-suspicious-query-marker.yaml) (`network/dns-suspicious-query-marker.yaml`) | DNS demonstration query marker | `dns` | Query contains `tunnel-test`; not general DNS-tunneling detection. |
| [`powershell-network-connection`](../../rules/windows/network/powershell-network-connection.yaml) (`network/powershell-network-connection.yaml`) | PowerShell-associated network connection | `network` | Process-image suffix `\powershell.exe` or `\pwsh.exe`; no direction or destination verdict. |
| [`startup-folder-file-activity`](../../rules/windows/persistence/startup-folder-file-activity.yaml) (`persistence/startup-folder-file-activity.yaml`) | Startup-folder file activity | `file` | Target path contains `\Start Menu\Programs\Startup\`; not proof of persistence execution. |

## Python integration example

There is no Detection Engine CLI, API, or background service. In a Python 3.12
environment synced with the repository dependencies, make `backend` available
on the Python module search path (as the repository tests do). Replace the
example absolute repository path below with your checkout's absolute path.
This uses an unchanged synthetic fixture, not production data:

```python
from pathlib import Path

from app.detection import evaluate_event, load_detection_rules
from app.parsers import normalize_windows_event_xml

repository = Path("C:/path/to/soc-investigation-lab")
rule_root = repository / "rules" / "windows"
fixture = (
    repository / "tests" / "fixtures" / "windows" / "security" / "security_4625_failed_logon.xml"
)
event = normalize_windows_event_xml(fixture.read_text(encoding="utf-8"))
rules = load_detection_rules(rule_root)
matches = evaluate_event(event, rules)
assert [match.rule_id for match in matches] == ["failed-remote-authentication"]
```

The actual end-to-end tests also exercise safe in-memory XML variations,
negative events, absent fields, target filtering, multiple-match ordering, and
controlled failures. See [Testing](../testing.md) and
[`test_detection_pipeline.py`](../../tests/integration/test_detection_pipeline.py).

## Current limitations and planned downstream work

The engine handles one normalized event at a time. It has no stateful or
cross-event correlation, counters, frequency thresholds, time windows, regex,
Sigma compatibility, arbitrary expressions, remote rule fetching, or dynamic
plugins. The initial rules use exact case-sensitive text and narrow source
coverage; benign activity can match and differently spelled signals can miss.

v0.3.0 ends at `DetectionMatch`. Alert generation/lifecycle, analyst triage,
investigation workflow, evidence records, analyst notes, IOC/ATT&CK runtime
enrichment, verdicts, escalation, severity/priority workflows, persistence,
databases, backend API, and analyst web UI remain planned. Streaming/Kafka,
live telemetry collection, and distributed correlation are not implemented.
No match performs containment, remediation, or an autonomous security decision.
