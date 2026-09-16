"""Normalize supported Sysmon raw events without routing or detection logic."""

from collections.abc import Mapping

from pydantic import ValidationError

from app.models import (
    DnsContext,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    NormalizedEvent,
    ProcessContext,
    RawWindowsEvent,
)

from .errors import InvalidNormalizedEventError, UnsupportedEventError

_PROCESS_FIELDS = frozenset(
    {"Image", "ProcessId", "CommandLine", "ParentProcessId", "ParentImage", "User"}
)
_NETWORK_FIELDS = frozenset(
    {"SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Protocol", "ProcessId", "Image"}
)
_FILE_FIELDS = frozenset({"TargetFilename", "ProcessId", "Image"})
_DNS_FIELDS = frozenset({"QueryName", "QueryStatus", "QueryResults", "ProcessId", "Image"})


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


def _decimal_integer(value: str, field: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise InvalidNormalizedEventError(f"{field} must be a valid decimal integer") from exc
    if result < 0:
        raise InvalidNormalizedEventError(f"{field} must be non-negative")
    return result


def _required_integer(data: Mapping[str, str], field: str) -> int:
    return _decimal_integer(_required_text(data, field), field)


def _optional_integer(data: Mapping[str, str], field: str) -> int | None:
    value = _optional_text(data.get(field))
    return None if value is None else _decimal_integer(value, field)


def _process_context(data: Mapping[str, str]) -> ProcessContext:
    return ProcessContext(
        image=_required_text(data, "Image"),
        process_id=_required_integer(data, "ProcessId"),
        command_line=_optional_text(data.get("CommandLine")),
        parent_process_id=_optional_integer(data, "ParentProcessId"),
        parent_image=_optional_text(data.get("ParentImage")),
        user=_optional_text(data.get("User")),
    )


def _network_context(data: Mapping[str, str]) -> NetworkContext:
    return NetworkContext.model_validate(
        {
            "source_ip": _required_text(data, "SourceIp"),
            "source_port": _required_integer(data, "SourcePort"),
            "destination_ip": _required_text(data, "DestinationIp"),
            "destination_port": _required_integer(data, "DestinationPort"),
            "protocol": _optional_text(data.get("Protocol")),
            "process_id": _optional_integer(data, "ProcessId"),
            "process_image": _optional_text(data.get("Image")),
        }
    )


def _file_context(data: Mapping[str, str]) -> FileContext:
    return FileContext(
        target_path=_required_text(data, "TargetFilename"),
        process_id=_optional_integer(data, "ProcessId"),
        process_image=_optional_text(data.get("Image")),
    )


def _dns_context(data: Mapping[str, str]) -> DnsContext:
    return DnsContext(
        query_name=_required_text(data, "QueryName"),
        query_status=_optional_text(data.get("QueryStatus")),
        query_results=_optional_text(data.get("QueryResults")),
        process_id=_optional_integer(data, "ProcessId"),
        process_image=_optional_text(data.get("Image")),
    )


def normalize_sysmon_event(raw: RawWindowsEvent) -> NormalizedEvent:
    """Normalize only Sysmon 1, 3, 11 and 22, preserving unused source fields."""
    if (
        raw.provider != "Microsoft-Windows-Sysmon"
        or raw.channel != "Microsoft-Windows-Sysmon/Operational"
        or raw.event_id not in {1, 3, 11, 22}
    ):
        raise UnsupportedEventError(
            f"unsupported Sysmon identity: {raw.provider!r}, {raw.channel!r}, {raw.event_id}"
        )

    try:
        context: ProcessContext | NetworkContext | FileContext | DnsContext
        if raw.event_id == 1:
            category = EventCategory.PROCESS
            context = _process_context(raw.event_data)
            consumed_fields = _PROCESS_FIELDS
        elif raw.event_id == 3:
            category = EventCategory.NETWORK
            context = _network_context(raw.event_data)
            consumed_fields = _NETWORK_FIELDS
        elif raw.event_id == 11:
            category = EventCategory.FILE
            context = _file_context(raw.event_data)
            consumed_fields = _FILE_FIELDS
        else:
            category = EventCategory.DNS
            context = _dns_context(raw.event_data)
            consumed_fields = _DNS_FIELDS

        return NormalizedEvent(
            source=EventSource.SYSMON,
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
        raise InvalidNormalizedEventError("invalid normalized Sysmon event") from exc
