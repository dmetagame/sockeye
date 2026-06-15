from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

import web.app as app_module
from web.jobs import JobManager, JobRecord


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class FakeManager:
    def __init__(self, report_path: Path) -> None:
        self.max_pending = 5
        self.report = report_path
        self.job = JobRecord(
            id="00000000-0000-0000-0000-000000000001",
            index="security",
            earliest="-48h",
            status="succeeded",
            report_file=report_path.name,
            turns=8,
            tool_calls=4,
        )
        self.job.events = [
            {"id": 1, "at": self.job.created_at, "type": "queued"},
            {"id": 2, "at": self.job.updated_at, "type": "completed"},
        ]

    def list_jobs(self) -> list[dict[str, object]]:
        return [self.job.public()]

    def get(self, job_id: str) -> JobRecord | None:
        return self.job if job_id == self.job.id else None

    def create(self, index: str, earliest: str) -> JobRecord:
        self.job.index = index
        self.job.earliest = earliest
        return self.job

    def report_path(self, job: JobRecord) -> Path | None:
        return self.report if job.id == self.job.id else None

    async def shutdown(self) -> None:
        return None


@pytest.mark.anyio
async def test_health_and_security_headers(monkeypatch, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "manager", FakeManager(report))
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.anyio
async def test_jobs_require_and_accept_api_key(monkeypatch, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "manager", FakeManager(report))
    monkeypatch.setenv("SOCKEYE_WEB_API_KEY", "test-secret-that-is-long-enough")
    monkeypatch.delenv("SOCKEYE_ALLOW_UNAUTHENTICATED", raising=False)
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/api/jobs")).status_code == 401
        response = await client.get(
            "/api/jobs",
            headers={"Authorization": "Bearer test-secret-that-is-long-enough"},
        )
    assert response.status_code == 200
    assert response.json()["jobs"][0]["status"] == "succeeded"


@pytest.mark.anyio
async def test_create_job_validates_scope(monkeypatch, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "manager", FakeManager(report))
    monkeypatch.setenv("SOCKEYE_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.delenv("SOCKEYE_WEB_API_KEY", raising=False)
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        invalid = await client.post(
            "/api/jobs", json={"index": "security | delete", "earliest": "-48h"}
        )
        valid = await client.post(
            "/api/jobs", json={"index": "security", "earliest": "-24h"}
        )
    assert invalid.status_code == 422
    assert valid.status_code == 202
    assert valid.json()["earliest"] == "-24h"


@pytest.mark.anyio
async def test_report_endpoint(monkeypatch, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n\nEvidence.\n", encoding="utf-8")
    fake = FakeManager(report)
    monkeypatch.setattr(app_module, "manager", fake)
    returned_report = await app_module.get_report(fake.job.id, download=False)
    assert Path(returned_report.path) == report
    assert returned_report.media_type.startswith("text/markdown")


def test_sse_format_is_parseable() -> None:
    event = app_module.format_sse("progress", {"type": "tool_call"}, event_id=4)
    assert event.startswith("id: 4\nevent: progress\n")
    data = next(line[6:] for line in event.splitlines() if line.startswith("data: "))
    assert json.loads(data) == {"type": "tool_call"}


def test_job_manager_recovers_interrupted_job(tmp_path: Path) -> None:
    metadata = tmp_path / "jobs"
    metadata.mkdir(parents=True)
    job = JobRecord(id="job-1", index="security", earliest="-48h", status="running")
    (metadata / "job-1.json").write_text(json.dumps(job.__dict__), encoding="utf-8")
    manager = JobManager(tmp_path)
    recovered = manager.get("job-1")
    assert recovered is not None
    assert recovered.status == "failed"
    assert "restarted" in (recovered.error or "")


def test_report_path_cannot_escape_state_directory(tmp_path: Path) -> None:
    manager = JobManager(tmp_path)
    job = JobRecord(
        id="job-2",
        index="security",
        earliest="-48h",
        status="succeeded",
        report_file="../../etc/passwd",
    )
    assert manager.report_path(job) is None
