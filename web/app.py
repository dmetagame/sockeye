"""FastAPI application for the Sockeye web dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import pathlib
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agent.triage import bool_env
from web.jobs import FINAL_STATES, JobManager

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "web" / "static"
STATE_DIR = pathlib.Path(os.getenv("SOCKEYE_STATE_DIR", ROOT / "reports" / "web"))
manager = JobManager(STATE_DIR)


class CreateJobRequest(BaseModel):
    index: str = Field(default="security", pattern=r"^[A-Za-z0-9_-]+$", max_length=64)
    earliest: str = Field(default="-48h", pattern=r"^-[1-9][0-9]*[smhdw](?:@[smhdw])?$")


class SecurityHeadersMiddleware:
    """Add security headers without buffering streaming responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
                )
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=()"
                )
                if scope.get("path", "").startswith("/api/"):
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


def format_sse(event_type: str, payload: dict[str, object], event_id: int | None = None) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.extend(
        [
            f"event: {event_type}",
            f"data: {json.dumps(payload, separators=(',', ':'))}",
            "",
            "",
        ]
    )
    return "\n".join(lines)


async def require_api_key(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    expected = os.getenv("SOCKEYE_WEB_API_KEY")
    if not expected:
        if bool_env("SOCKEYE_ALLOW_UNAUTHENTICATED"):
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Web API authentication is not configured.",
        )
    if len(expected) < 24:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOCKEYE_WEB_API_KEY must contain at least 24 characters.",
        )
    supplied = x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await manager.shutdown()


app = FastAPI(
    title="Sockeye",
    description="Agentic SOC triage on the official Splunk MCP Server",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readiness() -> JSONResponse:
    missing = [
        name
        for name in ("SPLUNK_MCP_URL", "SPLUNK_MCP_TOKEN")
        if not os.getenv(name)
    ]
    if not os.getenv("ANTHROPIC_API_KEY") and bool_env(
        "SOCKEYE_REQUIRE_ANTHROPIC_API_KEY", True
    ):
        missing.append("ANTHROPIC_API_KEY")
    web_key = os.getenv("SOCKEYE_WEB_API_KEY")
    if not web_key and not bool_env("SOCKEYE_ALLOW_UNAUTHENTICATED"):
        missing.append("SOCKEYE_WEB_API_KEY")
    invalid = ["SOCKEYE_WEB_API_KEY"] if web_key and len(web_key) < 24 else []
    ready = not missing and not invalid
    payload = {
        "status": "ready" if ready else "not_ready",
        "missing": missing,
        "invalid": invalid,
    }
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/api/config")
async def config() -> dict[str, object]:
    allow_unauthenticated = bool_env("SOCKEYE_ALLOW_UNAUTHENTICATED")
    auth_configured = bool(os.getenv("SOCKEYE_WEB_API_KEY"))
    return {
        "auth_required": auth_configured,
        "auth_configured": auth_configured,
        "allow_unauthenticated": allow_unauthenticated,
        "configuration_error": not auth_configured and not allow_unauthenticated,
        "max_pending_jobs": manager.max_pending,
    }


@app.get("/api/jobs", dependencies=[Depends(require_api_key)])
async def list_jobs() -> dict[str, object]:
    return {"jobs": manager.list_jobs()}


@app.post(
    "/api/jobs",
    dependencies=[Depends(require_api_key)],
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_job(payload: CreateJobRequest) -> dict[str, object]:
    try:
        job = manager.create(payload.index, payload.earliest)
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return job.public()


@app.get("/api/jobs/{job_id}", dependencies=[Depends(require_api_key)])
async def get_job(job_id: str) -> dict[str, object]:
    job = manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job.public()


@app.get("/api/jobs/{job_id}/events", dependencies=[Depends(require_api_key)])
async def job_events(job_id: str, request: Request, after: int = 0) -> StreamingResponse:
    job = manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    async def stream() -> AsyncIterator[str]:
        cursor = max(after, 0)
        idle_ticks = 0
        while True:
            current = manager.get(job_id)
            if current is None:
                return
            pending = [event for event in current.events if int(event["id"]) > cursor]
            for event in pending:
                cursor = int(event["id"])
                yield format_sse("progress", event, cursor)
            if current.status in FINAL_STATES and cursor >= len(current.events):
                yield format_sse("end", current.public())
                return
            if await request.is_disconnected():
                return
            idle_ticks += 1
            if idle_ticks % 20 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no"},
    )


@app.get("/api/jobs/{job_id}/report", dependencies=[Depends(require_api_key)])
async def get_report(job_id: str, download: bool = False) -> FileResponse:
    job = manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    path = manager.report_path(job)
    if path is None:
        raise HTTPException(status_code=404, detail="Report is not available.")
    disposition = "attachment" if download else "inline"
    return FileResponse(
        path,
        media_type="text/markdown; charset=utf-8",
        filename=f"sockeye-{job.id}.md" if download else None,
        content_disposition_type=disposition,
    )


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
