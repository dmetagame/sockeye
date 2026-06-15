"""Durable, bounded background-job management for Sockeye triage runs."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import logging
import os
import pathlib
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from agent.triage import run

LOGGER = logging.getLogger(__name__)
FINAL_STATES = {"succeeded", "failed"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass
class JobRecord:
    id: str
    index: str
    earliest: str
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    report_file: str | None = None
    turns: int | None = None
    cost_usd: float | None = None
    tool_calls: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    def public(self, include_events: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_events:
            data.pop("events")
        data["report_url"] = (
            f"/api/jobs/{self.id}/report" if self.report_file else None
        )
        return data


class JobManager:
    """Run one Claude investigation at a time and persist job metadata."""

    def __init__(self, state_dir: pathlib.Path) -> None:
        self.state_dir = state_dir
        self.report_dir = state_dir / "reports"
        self.metadata_dir = state_dir / "jobs"
        self.jobs: dict[str, JobRecord] = {}
        self.tasks: set[asyncio.Task[None]] = set()
        self.worker = asyncio.Semaphore(1)
        self.max_pending = int(os.getenv("SOCKEYE_MAX_PENDING_JOBS", "5"))
        self.max_history = int(os.getenv("SOCKEYE_MAX_JOB_HISTORY", "100"))
        self._load()

    def _load(self) -> None:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.metadata_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                job = JobRecord(**data)
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                LOGGER.warning("Ignoring invalid job metadata: %s", path)
                continue
            if job.status not in FINAL_STATES:
                job.status = "failed"
                job.error = "The web service restarted before this job completed."
                job.completed_at = utc_now()
                job.updated_at = job.completed_at
                self._persist(job)
            self.jobs[job.id] = job
        self._prune_history()

    def _metadata_path(self, job_id: str) -> pathlib.Path:
        return self.metadata_dir / f"{job_id}.json"

    def _persist(self, job: JobRecord) -> None:
        path = self._metadata_path(job.id)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(asdict(job), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    def _prune_history(self) -> None:
        completed = sorted(
            (job for job in self.jobs.values() if job.status in FINAL_STATES),
            key=lambda job: job.created_at,
            reverse=True,
        )
        for job in completed[self.max_history :]:
            self.jobs.pop(job.id, None)
            self._metadata_path(job.id).unlink(missing_ok=True)
            if job.report_file:
                (self.report_dir / job.report_file).unlink(missing_ok=True)

    def list_jobs(self) -> list[dict[str, Any]]:
        jobs = sorted(self.jobs.values(), key=lambda job: job.created_at, reverse=True)
        return [job.public() for job in jobs[: self.max_history]]

    def get(self, job_id: str) -> JobRecord | None:
        return self.jobs.get(job_id)

    def pending_count(self) -> int:
        return sum(job.status in {"queued", "running"} for job in self.jobs.values())

    def create(self, index: str, earliest: str) -> JobRecord:
        if self.pending_count() >= self.max_pending:
            raise RuntimeError("The investigation queue is full. Try again later.")
        job = JobRecord(id=str(uuid.uuid4()), index=index, earliest=earliest)
        job.events.append(
            {
                "id": 1,
                "at": job.created_at,
                "type": "queued",
                "message": "Investigation queued",
            }
        )
        self.jobs[job.id] = job
        self._persist(job)
        task = asyncio.create_task(self._execute(job))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def _execute(self, job: JobRecord) -> None:
        async with self.worker:
            job.status = "running"
            job.started_at = utc_now()
            job.updated_at = job.started_at
            self._append_event(job, {"type": "running", "message": "Agent started"})

            async def progress(event: dict[str, Any]) -> None:
                if event.get("type") == "tool_call":
                    job.tool_calls = int(event.get("number", job.tool_calls))
                self._append_event(job, event)

            arguments = argparse.Namespace(
                index=job.index,
                earliest=job.earliest,
                model=os.getenv("SOCKEYE_MODEL", "sonnet"),
                max_turns=int(os.getenv("SOCKEYE_MAX_TURNS", "40")),
                output_dir=self.report_dir,
            )
            try:
                outcome = await run(arguments, progress=progress)
                job.status = "succeeded"
                job.report_file = outcome.report_path.name
                job.turns = outcome.turns
                job.cost_usd = outcome.cost_usd
                job.tool_calls = outcome.tool_calls
                job.completed_at = utc_now()
                job.updated_at = job.completed_at
                self._persist(job)
            except Exception as exc:  # Errors are persisted; traces stay server-side.
                LOGGER.exception("Sockeye job %s failed", job.id)
                job.status = "failed"
                job.error = str(exc)[:1000]
                job.completed_at = utc_now()
                job.updated_at = job.completed_at
                self._append_event(
                    job,
                    {"type": "failed", "message": job.error},
                )
            finally:
                self._prune_history()

    def _append_event(self, job: JobRecord, event: dict[str, Any]) -> None:
        entry = {
            "id": len(job.events) + 1,
            "at": utc_now(),
            **event,
        }
        job.events.append(entry)
        job.updated_at = entry["at"]
        self._persist(job)

    def report_path(self, job: JobRecord) -> pathlib.Path | None:
        if not job.report_file:
            return None
        candidate = (self.report_dir / job.report_file).resolve()
        if candidate.parent != self.report_dir.resolve() or not candidate.is_file():
            return None
        return candidate

    async def shutdown(self) -> None:
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=10)
        if pending:
            LOGGER.warning("Timed out waiting for %d job task(s) to stop", len(pending))
