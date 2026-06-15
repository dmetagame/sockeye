from __future__ import annotations

import argparse
import asyncio
import pathlib

import pytest

from agent import triage


def args(**overrides: object) -> argparse.Namespace:
    values = {
        "index": "security",
        "earliest": "-48h",
        "model": "sonnet",
        "max_turns": 40,
        "output_dir": pathlib.Path("reports"),
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def valid_report() -> str:
    return "\n".join(
        [
            "# SOC Triage",
            "## Verdict",
            "Confirmed incident. " + "Evidence-backed summary. " * 20,
            "## Timeline",
            "| Time | Event |",
            "|---|---|",
            "| 12:00 | Login |",
            "## IOCs",
            "- `192.0.2.10`",
            "## Evidence",
            "```spl",
            "search index=security earliest=-48h latest=now | stats count",
            "```",
            "## Recommended actions",
            "1. Isolate the affected host.",
        ]
    )


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
def test_loopback_detection(host: str) -> None:
    assert triage.is_loopback_host(host)


def test_loopback_detection_rejects_lookalike() -> None:
    assert not triage.is_loopback_host("localhost.example.com")


def test_validate_config_rejects_remote_http() -> None:
    with pytest.raises(triage.SockeyeError, match="unencrypted remote"):
        triage.validate_config(args(), "http://splunk.example.com:8089/services/mcp", "token")


def test_build_options_is_read_only_and_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOCKEYE_ALLOW_INSECURE_REMOTE_HTTP", raising=False)
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-nonexistent")
    options = triage.build_options(
        args(), "http://localhost:8089/services/mcp", "secret-token"
    )
    assert options.model == "sonnet"
    assert options.strict_mcp_config is True
    assert options.setting_sources == []
    assert options.tools is None
    assert options.permission_mode == "dontAsk"
    assert options.allowed_tools == triage.READ_ONLY_SPLUNK_TOOLS
    assert options.mcp_servers["splunk"]["command"] == "mcp-remote"
    assert options.mcp_servers["splunk"]["args"] == [
        "http://localhost:8089/services/mcp",
        "--header",
        "Authorization: Bearer secret-token",
    ]
    assert "ANTHROPIC_MODEL" not in options.env


def test_report_validation_accepts_complete_report() -> None:
    triage.validate_report(valid_report())


def test_report_validation_rejects_placeholder_spl() -> None:
    report = valid_report().replace("| stats count", "OR ... | stats count")
    with pytest.raises(triage.SockeyeError, match="placeholder"):
        triage.validate_report(report)


def test_execution_audit_uses_exact_query() -> None:
    query = "search index=security earliest=-48h latest=now | stats count by host"
    audit = triage.render_tool_audit(
        [{"name": "mcp__splunk__splunk_run_query", "input": {"query": query}}]
    )
    assert query in audit
    assert "**1** Splunk MCP tool call" in audit


def test_only_approved_splunk_denials_are_fatal() -> None:
    denials = [
        {"tool_name": "Bash", "tool_input": {"command": "whoami"}},
        {
            "tool_name": "mcp__splunk__splunk_run_query",
            "tool_input": {"query": "search index=security | stats count"},
        },
    ]
    assert triage.required_permission_denials(denials) == [denials[1]]


def test_write_report_is_utf8_and_atomic(tmp_path: pathlib.Path) -> None:
    path = triage.write_report(valid_report(), tmp_path)
    assert path.read_text(encoding="utf-8").endswith("\n")
    assert not path.with_suffix(".md.tmp").exists()


def test_progress_callback_supports_async_and_sync() -> None:
    events: list[dict[str, object]] = []

    async def async_callback(event: dict[str, object]) -> None:
        events.append(event)

    asyncio.run(triage.emit_progress(async_callback, {"type": "async"}))
    asyncio.run(triage.emit_progress(events.append, {"type": "sync"}))
    assert [event["type"] for event in events] == ["async", "sync"]
