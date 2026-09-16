"""Normalize supported Windows Security raw events into typed domain events."""

from collections.abc import Mapping

from pydantic import ValidationError

from app.models import (
    AuthenticationContext,
    AuthenticationOutcome,
    EventCategory,
    EventSource,
    NormalizedEvent,
    ProcessContext,
    RawWindowsEvent,
)

from .errors import InvalidNormalizedEventError, UnsupportedEventError

_AUTHENTICATION_FIELDS = frozenset(
    {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "IpPort", "WorkstationName"}
)
_PROCESS_FIELDS = frozenset(
    {
        "NewProcessName",
        "NewProcessId",
        "CommandLine",
        "ProcessId",
        "ParentProcessName",
        "SubjectUserName",
    }
)


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in {"", "-"} else stripped


def _required_text(data: Mapping[str, str], field: str) -> str:
    value = _optional_text(data.get(field))
    if value is None:
        raise InvalidNormalizedEventError(f"{field} is required")
    return value


def _parse_non_negative_integer(value: str, field: str, *, base: int = 10) -> int:
    try:
        result = int(value, base)
    except ValueError as exc:
        raise InvalidNormalizedEventError(f"{field} must be a valid integer") from exc
    if result < 0:
        raise InvalidNormalizedEventError(f"{field} must be non-negative")
    return result


def _optional_decimal_integer(data: Mapping[str, str], field: str) -> int | None:
    value = _optional_text(data.get(field))
    return None if value is None else _parse_non_negative_integer(value, field)


def _windows_integer(value: str, field: str) -> int:
    base = 16 if value.startswith(("0x", "0X")) else 10
    return _parse_non_negative_integer(value, field, base=base)


def _optional_windows_integer(data: Mapping[str, str], field: str) -> int | None:
    value = _optional_text(data.get(field))
    return None if value is None else _windows_integer(value, field)


def _authentication_context(
    data: Mapping[str, str],
    outcome: AuthenticationOutcome,
) -> AuthenticationContext:
    return AuthenticationContext.model_validate(
        {
            "outcome": outcome,
            "user": _optional_text(data.get("TargetUserName")),
            "domain": _optional_text(data.get("TargetDomainName")),
            "logon_type": _optional_decimal_integer(data, "LogonType"),
            "source_ip": _optional_text(data.get("IpAddress")),
            "source_port": _optional_decimal_integer(data, "IpPort"),
            "workstation": _optional_text(data.get("WorkstationName")),
        }
    )


def _process_context(data: Mapping[str, str]) -> ProcessContext:
    return ProcessContext(
        image=_required_text(data, "NewProcessName"),
        process_id=_windows_integer(_required_text(data, "NewProcessId"), "NewProcessId"),
        command_line=_optional_text(data.get("CommandLine")),
        parent_process_id=_optional_windows_integer(data, "ProcessId"),
        parent_image=_optional_text(data.get("ParentProcessName")),
        user=_optional_text(data.get("SubjectUserName")),
    )


def normalize_windows_security_event(raw: RawWindowsEvent) -> NormalizedEvent:
    """Normalize only Security 4624, 4625 and 4688, preserving unused source data."""
    if (
        raw.provider != "Microsoft-Windows-Security-Auditing"
        or raw.channel != "Security"
        or raw.event_id not in {4624, 4625, 4688}
    ):
        raise UnsupportedEventError(
            f"unsupported Windows Security identity: {raw.provider!r}, "
            f"{raw.channel!r}, {raw.event_id}"
        )

    try:
        context: AuthenticationContext | ProcessContext
        if raw.event_id == 4688:
            category = EventCategory.PROCESS
            context = _process_context(raw.event_data)
            consumed_fields = _PROCESS_FIELDS
        else:
            category = EventCategory.AUTHENTICATION
            outcome = (
                AuthenticationOutcome.SUCCESS
                if raw.event_id == 4624
                else AuthenticationOutcome.FAILURE
            )
            context = _authentication_context(raw.event_data, outcome)
            consumed_fields = _AUTHENTICATION_FIELDS

        return NormalizedEvent(
            source=EventSource.WINDOWS_SECURITY,
            provider=raw.provider,
            event_id=raw.event_id,
            channel=raw.channel,
            timestamp=raw.timestamp,
            computer=raw.computer,
            record_id=raw.record_id,
            category=category,
            context=context,
            source_data={
                name: value for name, value in raw.event_data.items() if name not in consumed_fields
            },
        )
    except ValidationError as exc:
        raise InvalidNormalizedEventError("invalid normalized Windows Security event") from exc
