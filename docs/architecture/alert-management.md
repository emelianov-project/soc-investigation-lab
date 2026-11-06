# Alert Management Architecture

**v0.4.0 — Alert Management is implemented, pending release.** The released
[v0.3.0 Detection Engine](detection-engine.md) produces `DetectionMatch` values.
Alert Management consumes one validated match with a TRUE root outcome and
preserves why the rule matched. The
[Alert Management contract](../alert-management-scope.md) defines this boundary.

```text
DetectionMatch → create_alert() → Alert
  → lifecycle, severity, and priority operations → list_alerts() → tuple[Alert, ...]
```

The queue is a stateless read of a caller-supplied collection. Investigation,
analyst verdicts, escalation, enrichment, durable storage, an HTTP API, a web
UI, notifications, streaming, and live telemetry collection are outside this
implemented boundary. Triage decisions and severity assignments are explicit
caller actions.

## Components and public API

| Component | Responsibility |
| --- | --- |
| [Alert model and enums](../../backend/app/models/alert.py) | Validate the identity, lifecycle state, policy values, timestamps, and owned match evidence. |
| [Creation](../../backend/app/alerts/creation.py) | Construct a new Alert from validated detection evidence and an explicit identity and instant. |
| [Lifecycle](../../backend/app/alerts/lifecycle.py) | Acknowledge or close an Alert through the permitted state transitions. |
| [Severity and priority](../../backend/app/alerts/policy.py) | Apply independent changes to active Alerts. |
| [Queue](../../backend/app/alerts/queue.py) | Validate the entire collection, filter it, and return detached Alert values in a deterministic order. |
| [Private validation](../../backend/app/alerts/_validation.py) | Revalidate Alert snapshots at operation boundaries and normalize supplied change times. |

Import the six functions and their public errors from `app.alerts`. Import
`Alert`, `AlertState`, `AlertSeverity`, `AlertPriority`, and `DetectionMatch`
from `app.models`. The public function signatures are:

```python
def create_alert(
    match: DetectionMatch,
    alert_id: str,
    created_at: datetime,
    *,
    severity: AlertSeverity = AlertSeverity.UNASSIGNED,
    priority: AlertPriority = AlertPriority.NORMAL,
) -> Alert: ...


def acknowledge_alert(alert: Alert, at: datetime) -> Alert: ...
def close_alert(alert: Alert, at: datetime) -> Alert: ...
def set_severity(alert: Alert, value: AlertSeverity, changed_at: datetime) -> Alert: ...
def set_priority(alert: Alert, value: AlertPriority, changed_at: datetime) -> Alert: ...


def list_alerts(
    alerts: Collection[Alert],
    *,
    states: set[AlertState] | frozenset[AlertState] | None = None,
    severities: set[AlertSeverity] | frozenset[AlertSeverity] | None = None,
    priorities: set[AlertPriority] | frozenset[AlertPriority] | None = None,
) -> tuple[Alert, ...]: ...
```

## Identity, evidence, and time

- Supply a stable `alert_id` of 1–128 ASCII characters matching
  `[a-z0-9]+(?:-[a-z0-9]+)*`. Creation generates no identifier and keeps no
  registration or deduplication state. Separate calls can assign different
  IDs to the same match.
- The frozen `Alert` owns a detached, lossless `source_match` snapshot with
  the rule ID, version and title, typed normalized event, root outcome, and
  complete ordered condition trace. Reading `source_match` gives a defensive
  copy. Alert operations preserve the evidence without rerunning detection or
  mutating the original match, event, or Alert.
- Supply an explicit timezone-aware `datetime`. Naive datetimes, strings,
  and invalid instants fail validation. Creation sets `created_at`,
  `state_changed_at`, and `updated_at` to the same UTC instant and starts in
  `NEW`. Updates compare UTC instants and require a time at or after the
  current `updated_at`. A real lifecycle transition updates both change
  timestamps. A policy change updates only `updated_at`. Stored times obey
  `created_at <= state_changed_at <= updated_at`, and `created_at` stays fixed.

## Lifecycle and independent policy values

`acknowledge_alert` moves `NEW` to `ACKNOWLEDGED`, and `close_alert` moves
`ACKNOWLEDGED` to `CLOSED`. Acknowledging an already acknowledged Alert or
closing an already closed Alert validates the input and time, then returns
an equivalent value with the original timestamps. Direct closure from `NEW`
and reopening a `CLOSED` Alert fail. Closure records the end of queue work.

**Severity** expresses assigned security significance. The values are
`UNASSIGNED`, `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
`UNASSIGNED` is the creation default and denotes no assessment.
**Priority** expresses handling urgency. The values are `LOW`, `NORMAL`,
`HIGH`, and `URGENT`, with `NORMAL` as the creation default.

Assign each value explicitly using its own enum type. The operations accept
`NEW` and `ACKNOWLEDGED` Alerts. Changing one value preserves the other and
the lifecycle state. Assigning the existing value validates the request and
preserves the timestamps. Both assignments fail on `CLOSED` Alerts, even when
the supplied value matches the existing one.

## Queue behavior

`list_alerts` snapshots a finite, sized collection and validates every Alert
and its ID before filtering. Duplicate IDs fail the entire call, including
duplicates among Alerts the filters would exclude.

- With `states=None`, the queue selects `NEW` and `ACKNOWLEDGED`. Use
  `states={AlertState.CLOSED}` for closed Alerts or `states=set(AlertState)`
  for all states. Omitted severity and priority filters are unrestricted.
- Explicit filters must be nonempty built-in `set` or `frozenset` values of
  the exact enum type. Matching uses OR within a filter and AND across
  filters. Empty input or no matches returns `()`.
- Ordering is priority descending (`URGENT`, `HIGH`, `NORMAL`, `LOW`), then
  severity descending (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`,
  `UNASSIGNED`), then oldest UTC `created_at`, then ASCII `alert_id` ascending.
  The placement of `UNASSIGNED` applies only to presentation.

Equal validated inputs yield equivalent values with explicit IDs and times.
Queue order is independent of collection iteration order.

## Errors and evidence safety

| Public error | Operation boundary |
| --- | --- |
| `AlertCreationError` | Invalid match, ID, creation instant, severity, or priority. |
| `AlertTransitionError` | Invalid Alert snapshot or instant, backdated transition, or forbidden state change. |
| `AlertPolicyError` | Invalid Alert snapshot or enum, invalid or backdated instant, or assignment to a closed Alert. |
| `AlertQueueError` | Invalid collection, Alert snapshot, filter, or duplicate Alert ID. |

The errors expose a `reason` and a safe `field` name when available. A failed
operation leaves its inputs intact and produces no partial result. Public
Alert diagnostics omit match evidence and raw validation details. Evidence
itself can include hostnames, source data, and trace values. Apply the
[security policy](../../SECURITY.md) before logging or exporting it.

## Offline Python example

After a locked dependency sync, run the snippet from the repository root
with `uv run --no-sync python`. It reads the checked-in synthetic 4625
fixture, which matches the checked-in `failed-remote-authentication` rule.
Only Alert metadata is selected for display.

```python
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

repository = Path.cwd()
sys.path.insert(0, str(repository / "backend"))

from app.alerts import acknowledge_alert, close_alert, create_alert, list_alerts, set_priority
from app.detection import evaluate_event, load_detection_rules
from app.models import AlertPriority, AlertState
from app.parsers import normalize_windows_event_xml

fixture = repository / "tests/fixtures/windows/security/security_4625_failed_logon.xml"
event = normalize_windows_event_xml(fixture.read_text(encoding="utf-8"))
rules = load_detection_rules(repository / "rules/windows")
(match,) = evaluate_event(event, rules)
assert match.rule_id == "failed-remote-authentication"

created_at = datetime(2026, 10, 1, 12, tzinfo=UTC)
alert = create_alert(match, "example-failed-logon", created_at)
alert = acknowledge_alert(alert, created_at + timedelta(minutes=1))
alert = set_priority(alert, AlertPriority.HIGH, created_at + timedelta(minutes=2))
queue = list_alerts([alert], priorities={AlertPriority.HIGH})
print([(item.alert_id, item.state.value) for item in queue])
# [('example-failed-logon', 'acknowledged')]

closed = close_alert(alert, created_at + timedelta(minutes=3))
assert list_alerts([closed], states={AlertState.CLOSED}) == (closed,)
```

See [Alert Management coverage](../testing.md#alert-management-coverage) for
the XML-to-Alert integration cases and failure paths.
