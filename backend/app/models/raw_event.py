"""Source-shaped domain contract for ingested Windows Event XML."""

from collections.abc import Mapping
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, StrictStr

NonEmptyString = Annotated[StrictStr, Field(min_length=1)]
NonNegativeInteger = Annotated[StrictInt, Field(ge=0)]
PositiveInteger = Annotated[StrictInt, Field(gt=0)]


class RawWindowsEvent(BaseModel):
    """Validated Windows Event metadata before source-specific normalization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: NonEmptyString
    event_id: PositiveInteger
    channel: NonEmptyString
    timestamp: AwareDatetime
    computer: NonEmptyString
    record_id: NonNegativeInteger | None = None
    event_data: Mapping[StrictStr, StrictStr] = Field(default_factory=dict)
