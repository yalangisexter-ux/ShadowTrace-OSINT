from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import register_default_collectors, router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Modular, evidence-first OSINT collection API.",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
async def startup() -> None:
    register_default_collectors()


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "shadowtrace-platform"}


app.include_router(router, prefix=settings.api_prefix)
