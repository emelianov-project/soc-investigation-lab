"""Validated domain contracts for normalized security events."""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictInt,
    StrictStr,
    model_validator,
)

NonEmptyString = Annotated[StrictStr, Field(min_length=1)]
NonNegativeInteger = Annotated[StrictInt, Field(ge=0)]
PositiveInteger = Annotated[StrictInt, Field(gt=0)]
Port = Annotated[StrictInt, Field(ge=0, le=65_535)]


class EventSource(StrEnum):
    """Supported sources of normalized events."""

    WINDOWS_SECURITY = "windows_security"
    SYSMON = "sysmon"


class EventCategory(StrEnum):
    """Supported normalized event categories."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    DNS = "dns"


class AuthenticationOutcome(StrEnum):
    """Supported authentication outcomes."""

    SUCCESS = "success"
    FAILURE = "failure"


class _NormalizedModel(BaseModel):
    """Shared validation policy for normalized-event domain models."""

    model_config = ConfigDict(extra="forbid")


class AuthenticationContext(_NormalizedModel):
    """Normalized context for an authentication event."""

    outcome: AuthenticationOutcome
    user: StrictStr | None = None
    domain: StrictStr | None = None
    logon_type: NonNegativeInteger | None = None
    source_ip: IPvAnyAddress | None = None
    source_port: Port | None = None
    workstation: StrictStr | None = None


class ProcessContext(_NormalizedModel):
    """Normalized context for a process-creation event."""

    image: NonEmptyString
    process_id: NonNegativeInteger | None = None
    command_line: StrictStr | None = None
    parent_process_id: NonNegativeInteger | None = None
    parent_image: StrictStr | None = None
    user: StrictStr | None = None


class NetworkContext(_NormalizedModel):
    """Normalized context for a network-connection event."""

    source_ip: IPvAnyAddress
    source_port: Port
    destination_ip: IPvAnyAddress
    destination_port: Port
    protocol: StrictStr | None = None
    process_id: NonNegativeInteger | None = None
    process_image: StrictStr | None = None


class FileContext(_NormalizedModel):
    """Normalized context for a file event."""

    target_path: NonEmptyString
    process_id: NonNegativeInteger | None = None
    process_image: StrictStr | None = None


class DnsContext(_NormalizedModel):
    """Normalized context for a DNS query event."""

    query_name: NonEmptyString
    query_status: StrictStr | None = None
    query_results: StrictStr | None = None
    process_id: NonNegativeInteger | None = None
    process_image: StrictStr | None = None


EventContext = AuthenticationContext | ProcessContext | NetworkContext | FileContext | DnsContext

_CONTEXT_TYPE_BY_CATEGORY: dict[EventCategory, type[_NormalizedModel]] = {
    EventCategory.AUTHENTICATION: AuthenticationContext,
    EventCategory.PROCESS: ProcessContext,
    EventCategory.NETWORK: NetworkContext,
    EventCategory.FILE: FileContext,
    EventCategory.DNS: DnsContext,
}


class NormalizedEvent(_NormalizedModel):
    """A validated, source-independent security event."""

    source: EventSource
    provider: NonEmptyString
    event_id: PositiveInteger
    channel: NonEmptyString
    timestamp: AwareDatetime
    computer: NonEmptyString
    record_id: NonNegativeInteger | None = None
    category: EventCategory
    context: EventContext
    source_data: dict[StrictStr, StrictStr] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_context_matches_category(self) -> Self:
        """Reject normalized events whose context disagrees with their category."""
        expected_context_type = _CONTEXT_TYPE_BY_CATEGORY[self.category]
        if not isinstance(self.context, expected_context_type):
            msg = f"category {self.category.value!r} requires {expected_context_type.__name__}"
            raise ValueError(msg)
        return self
