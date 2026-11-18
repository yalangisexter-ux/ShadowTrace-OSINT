from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field


class CollectionRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


class Observation(BaseModel):
    entity_type: str
    value: str
    relation: str | None = None
    source: str
    source_url: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    confidence: float = Field(default=0.5, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class CollectionResult(BaseModel):
    collector: str
    target: str
    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime


class Collector(Protocol):
    name: str
    version: str
    description: str

    async def collect(self, target: str) -> list[Observation]: ...
