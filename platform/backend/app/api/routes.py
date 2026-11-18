import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from app.core.contracts import CollectionRequest, CollectionResult
from app.core.registry import CollectorRegistry

router = APIRouter()
registry = CollectorRegistry()
_semaphore = asyncio.Semaphore(5)


def register_default_collectors() -> None:
    from app.collectors.domain import DomainCollector

    if not registry.list():
        registry.register(DomainCollector())


@router.get("/plugins")
async def list_plugins() -> dict:
    return {"items": registry.list()}


@router.post("/collect/domain", response_model=CollectionResult)
async def collect_domain(request: CollectionRequest) -> CollectionResult:
    from app.collectors.domain import DomainCollector

    started = datetime.now(UTC)
    collector = registry.get("domain.passive")
    try:
        async with _semaphore:
            observations = await collector.collect(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail="Collection provider timed out or was unavailable.") from exc
    return CollectionResult(
        collector=collector.name,
        target=DomainCollector.normalize_target(request.target),
        observations=observations,
        started_at=started,
        completed_at=datetime.now(UTC),
    )
