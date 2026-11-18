import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.contracts import CollectionRequest, CollectionResult
from app.core.registry import CollectorRegistry

router = APIRouter()
registry = CollectorRegistry()
_semaphore = asyncio.Semaphore(6)


def register_default_collectors() -> None:
    from app.collectors.domain import DomainCollector
    from app.collectors.email import EmailCollector
    from app.collectors.ip import IPCollector

    if not registry.list():
        registry.register(DomainCollector())
        registry.register(IPCollector())
        registry.register(EmailCollector())


class GenericCollectRequest(BaseModel):
    collector: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=253)


@router.get("/plugins")
async def list_plugins() -> dict:
    return {"items": registry.list()}


async def _run_collector(name: str, target: str) -> CollectionResult:
    started = datetime.now(UTC)
    try:
        collector = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {name}") from exc

    try:
        async with _semaphore:
            observations = await collector.collect(target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail="Collection provider timed out or was unavailable.") from exc

    return CollectionResult(
        collector=collector.name,
        target=target.strip(),
        observations=observations,
        started_at=started,
        completed_at=datetime.now(UTC),
    )


@router.post("/collect", response_model=CollectionResult)
async def collect_generic(request: GenericCollectRequest) -> CollectionResult:
    return await _run_collector(request.collector, request.target)


@router.post("/collect/domain", response_model=CollectionResult)
async def collect_domain(request: CollectionRequest) -> CollectionResult:
    from app.collectors.domain import DomainCollector

    result = await _run_collector("domain.passive", request.target)
    result.target = DomainCollector.normalize_target(request.target)
    return result


@router.post("/collect/ip", response_model=CollectionResult)
async def collect_ip(request: CollectionRequest) -> CollectionResult:
    from app.collectors.ip import IPCollector

    result = await _run_collector("ip.passive", request.target)
    result.target = IPCollector.normalize_target(request.target)
    return result


@router.post("/collect/email", response_model=CollectionResult)
async def collect_email(request: CollectionRequest) -> CollectionResult:
    from app.collectors.email import EmailCollector

    result = await _run_collector("email.passive", request.target)
    result.target = EmailCollector.normalize_target(request.target)
    return result
