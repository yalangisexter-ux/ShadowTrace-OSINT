from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import time
from collections import defaultdict, deque
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from app.config import settings
from app.db import Base, engine, get_db
from app.models import User, SearchRun, Evidence
from app.security import hash_password, verify_password, create_access_token, decode_access_token
from app.providers import search_username, validate_username, provider_count

@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.app_env.lower() == "production":
        if settings.secret_key == "local-development-only-change-me" or len(settings.secret_key) < 32:
            print("WARNING: SECRET_KEY is missing or too short. Set a strong SECRET_KEY (>=32 chars) in Render env vars.")
        if settings.database_url.startswith("sqlite") or not settings.database_url.strip():
            print("WARNING: DATABASE_URL is missing or points to SQLite. Set the Internal PostgreSQL URL in Render.")
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        print(f"WARNING: database init failed: {exc}")
    yield

app = FastAPI(title="ShadowTrace OSINT API", version="0.2.0", lifespan=lifespan)
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
if origins:
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
bearer = HTTPBearer(auto_error=False)
attempts = defaultdict(deque)

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class UsernameQuery(BaseModel):
    username: str = Field(min_length=2, max_length=30)

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token required")
    user_id = decode_access_token(credentials.credentials)
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user

def throttle(key: str, limit: int = 5, window: int = 60):
    now = time.monotonic()
    q = attempts[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests. Try again shortly.")
    q.append(now)

@app.get("/healthz")
def healthz():
    secret_ok = settings.secret_key != "local-development-only-change-me" and len(settings.secret_key) >= 32
    db_url = (settings.database_url or "").strip()
    db_ok = bool(db_url) and not db_url.startswith("sqlite")
    status = "ok" if secret_ok and db_ok else "degraded"
    return {
        "status": status,
        "service": "shadowtrace-osint",
        "version": "0.2.0",
        "providers": provider_count(),
        "time": datetime.now(timezone.utc).isoformat(),
        "config": {
            "secret_key_set": secret_ok,
            "database_configured": db_ok,
            "app_env": settings.app_env,
        },
    }

@app.post("/api/v1/auth/register", status_code=201)
def register(payload: Credentials, db: Session = Depends(get_db)):
    email = payload.email.lower()
    throttle("register:" + email, 3, 3600)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"access_token": create_access_token(user.id), "token_type": "bearer"}

@app.post("/api/v1/auth/login")
def login(payload: Credentials, db: Session = Depends(get_db)):
    email = payload.email.lower()
    throttle("login:" + email, 8, 300)
    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_access_token(user.id), "token_type": "bearer"}

@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()}

@app.post("/api/v1/search/username", status_code=201)
async def username_search(payload: UsernameQuery, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        username = validate_username(payload.username)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    throttle(f"search:{user.id}", 4, 60)
    results = await search_username(username)
    run = SearchRun(user_id=user.id, query_type="username", query_value=username)
    db.add(run)
    db.flush()
    for item in results:
        data = dict(item)
        checked = data.pop("checked_at")
        if isinstance(checked, str):
            checked = datetime.fromisoformat(checked)
        db.add(Evidence(run_id=run.id, checked_at=checked, **data))
    db.commit()
    db.refresh(run)
    candidates = sum(1 for r in results if r["status"] == "candidate")
    return {
        "id": run.id,
        "query_type": run.query_type,
        "query_value": run.query_value,
        "created_at": run.created_at.isoformat(),
        "summary": {"total": len(results), "candidates": candidates, "providers": provider_count()},
        "evidence": results,
        "notice": "Candidate matches are not identity verification. Review each source manually.",
    }

@app.get("/api/v1/search/runs")
def list_runs(user: User = Depends(current_user), db: Session = Depends(get_db)):
    runs = db.scalars(
        select(SearchRun).where(SearchRun.user_id == user.id).order_by(desc(SearchRun.created_at)).limit(50)
    ).all()
    return [
        {"id": r.id, "query_type": r.query_type, "query_value": r.query_value, "created_at": r.created_at.isoformat()}
        for r in runs
    ]

@app.get("/api/v1/search/runs/{run_id}")
def get_run(run_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    run = db.scalar(select(SearchRun).where(SearchRun.id == run_id, SearchRun.user_id == user.id))
    if not run:
        raise HTTPException(status_code=404, detail="Investigation not found")
    evidence = [
        {
            "provider": e.provider,
            "category": e.category,
            "profile_url": e.profile_url,
            "status": e.status,
            "http_status": e.http_status,
            "confidence": e.confidence,
            "detail": e.detail,
            "checked_at": e.checked_at.isoformat(),
        }
        for e in run.evidence
    ]
    return {
        "id": run.id,
        "query_type": run.query_type,
        "query_value": run.query_value,
        "created_at": run.created_at.isoformat(),
        "evidence": evidence,
    }

@app.get("/api/v1/search/runs/{run_id}/report.md")
def report_markdown(run_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    run = db.scalar(select(SearchRun).where(SearchRun.id == run_id, SearchRun.user_id == user.id))
    if not run:
        raise HTTPException(status_code=404, detail="Investigation not found")
    lines = [
        f"# ShadowTrace Investigation Report",
        f"",
        f"**Query:** `{run.query_value}` ({run.query_type})",
        f"**Run ID:** {run.id}",
        f"**Created:** {run.created_at.isoformat()}",
        f"",
        f"## Results",
        f"",
    ]
    for e in sorted(run.evidence, key=lambda x: (x.status != "candidate", x.provider)):
        lines.append(f"### {e.provider}")
        lines.append(f"- Status: **{e.status}** (confidence: {e.confidence})")
        lines.append(f"- URL: {e.profile_url}")
        lines.append(f"- HTTP: {e.http_status or '—'}")
        lines.append(f"- Detail: {e.detail}")
        lines.append(f"- Checked: {e.checked_at.isoformat()}")
        lines.append("")
    lines.append("---")
    lines.append("Candidate matches are not proof of identity. Manually verify every source.")
    lines.append("Generated by ShadowTrace OSINT — public-source only.")
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")

@app.get("/")
def index():
    return FileResponse(Path(__file__).parent.parent / "frontend" / "index.html")
