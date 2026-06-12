#!/usr/bin/env python3
"""Sockeye — agentic SOC triage on the official Splunk MCP Server.

Connects Claude to Splunk via the Model Context Protocol (the official
Splunk MCP Server app, streamable HTTP at /services/mcp), investigates
suspicious activity in index=security, and writes a markdown triage
report to reports/.

Auth: runs on the Claude Agent SDK, so it works with either a Claude
Pro/Max subscription (local `claude` login) or an ANTHROPIC_API_KEY.
"""
import asyncio
import datetime as dt
import os
import pathlib
import sys

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

MCP_URL = os.environ.get("SPLUNK_MCP_URL", "https://localhost:8089/services/mcp")
MCP_TOKEN = os.environ.get("SPLUNK_MCP_TOKEN")

SYSTEM = """You are Sockeye, a senior SOC analyst agent connected to a live
Splunk Enterprise instance through the official Splunk MCP Server.

Your job, every run:
1. Sweep index=security for the last 48h. Start broad: event volume by
   sourcetype, then auth failures by src_ip and user, looking for spray,
   brute-force, and impossible-travel patterns.
2. Follow the trail. If an IP or account looks hot, pivot: did any of its
   attempts SUCCEED? What did the account do afterwards (privilege
   escalation, lateral movement, large outbound transfers)?
3. Quantify everything with SPL via the Splunk MCP tools. Prefer `| stats`
   and `| timechart` with explicit earliest/latest bounds. Keep result sets
   small.
4. Finish with a triage report in markdown:
   - **Verdict** (benign / suspicious / CONFIRMED INCIDENT) and severity
   - **Timeline** of the attack phases with timestamps
   - **IOCs**: attacker IPs, compromised accounts, affected hosts
   - **Evidence**: the key SPL queries you ran and what they returned
   - **Recommended actions**: containment steps, ranked by urgency

Be precise: every claim in the report must be backed by a query you actually
ran this session. If the data is clean, say so — do not invent findings.
Your final message must be ONLY the markdown report."""


async def main() -> None:
    if not MCP_TOKEN:
        sys.exit("SPLUNK_MCP_TOKEN not set — run scripts/setup_splunk.sh, then `set -a; source .env`")

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM,
        mcp_servers={
            "splunk": {
                "type": "http",
                "url": MCP_URL,
                "headers": {"Authorization": f"Bearer {MCP_TOKEN}"},
            }
        },
        allowed_tools=["mcp__splunk"],   # every tool the Splunk MCP server exposes
        disallowed_tools=["Bash", "Write", "Edit"],
        max_turns=40,
        # local Splunk ships a self-signed cert on :8089
        env={**os.environ, "NODE_TLS_REJECT_UNAUTHORIZED": "0"},
    )

    report_text = ""
    async for message in query(
        prompt="Run a triage sweep of index=security now and report.",
        options=options,
    ):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    print(f"[tool] {block.name} {str(block.input)[:160]}")
                elif isinstance(block, TextBlock):
                    print(block.text)
                    report_text = block.text   # last text block = final report
        elif isinstance(message, ResultMessage):
            cost = f"${message.total_cost_usd:.4f}" if message.total_cost_usd else "subscription"
            print(f"\n[sockeye] done in {message.num_turns} turns ({cost})")

    if report_text:
        outdir = pathlib.Path(__file__).resolve().parent.parent / "reports"
        outdir.mkdir(exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = outdir / f"triage-{stamp}.md"
        path.write_text(report_text)
        print(f"[sockeye] report written to {path}")


if __name__ == "__main__":
    asyncio.run(main())
