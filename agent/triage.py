#!/usr/bin/env python3
"""Sockeye — agentic SOC triage on the official Splunk MCP Server.

Connects Claude to Splunk via MCP (streamable HTTP at /services/mcp),
investigates suspicious activity in index=security, and writes a
markdown triage report to reports/.
"""
import asyncio
import datetime as dt
import os
import pathlib
import ssl
import sys

import httpx
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_URL = os.environ.get("SPLUNK_MCP_URL", "https://localhost:8089/services/mcp")
MCP_TOKEN = os.environ.get("SPLUNK_MCP_TOKEN")
MODEL = "claude-opus-4-8"

SYSTEM = """You are Sockeye, a senior SOC analyst agent connected to a live
Splunk Enterprise instance through the official Splunk MCP Server.

Your job, every run:
1. Sweep index=security for the last 48h. Start broad: event volume by
   sourcetype, then auth failures by src_ip and user, looking for spray,
   brute-force, and impossible-travel patterns.
2. Follow the trail. If an IP or account looks hot, pivot: did any of its
   attempts SUCCEED? What did the account do afterwards (privilege
   escalation, lateral movement, large outbound transfers)?
3. Quantify everything with SPL via the MCP tools. Prefer `| stats`,
   `| timechart` and explicit earliest/latest bounds. Keep result sets small.
4. Finish with a triage report in markdown:
   - **Verdict** (benign / suspicious / CONFIRMED INCIDENT) and severity
   - **Timeline** of the attack phases with timestamps
   - **IOCs**: attacker IPs, compromised accounts, affected hosts
   - **Evidence**: the key SPL queries you ran and what they returned
   - **Recommended actions**: containment steps, ranked by urgency

Be precise: every claim in the report must be backed by a query you actually
ran this session. If the data is clean, say so — do not invent findings."""


def insecure_httpx_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    # local Splunk ships a self-signed cert on 8089
    return httpx.AsyncClient(
        verify=False, follow_redirects=True,
        headers=headers, timeout=timeout or httpx.Timeout(60), auth=auth,
    )


async def main() -> None:
    if not MCP_TOKEN:
        sys.exit("SPLUNK_MCP_TOKEN not set — run scripts/setup_splunk.sh, then `set -a; source .env`")

    client = AsyncAnthropic()
    async with streamablehttp_client(
        MCP_URL,
        headers={"Authorization": f"Bearer {MCP_TOKEN}"},
        httpx_client_factory=insecure_httpx_factory,
    ) as (read, write, _):
        async with ClientSession(read, write) as mcp:
            await mcp.initialize()
            tools_result = await mcp.list_tools()
            names = [t.name for t in tools_result.tools]
            print(f"[sockeye] connected to Splunk MCP server — {len(names)} tools: {', '.join(names)}")

            runner = client.beta.messages.tool_runner(
                model=MODEL,
                max_tokens=16000,
                thinking={"type": "adaptive"},
                system=SYSTEM,
                tools=[async_mcp_tool(t, mcp) for t in tools_result.tools],
                messages=[{
                    "role": "user",
                    "content": "Run a triage sweep of index=security now and report.",
                }],
            )

            report_text = ""
            async for message in runner:
                for block in message.content:
                    if block.type == "tool_use":
                        print(f"[tool] {block.name} {block.input}")
                    elif block.type == "text":
                        print(block.text)
                        report_text = block.text  # last text block = final report

    if report_text:
        outdir = pathlib.Path(__file__).resolve().parent.parent / "reports"
        outdir.mkdir(exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = outdir / f"triage-{stamp}.md"
        path.write_text(report_text)
        print(f"\n[sockeye] report written to {path}")


if __name__ == "__main__":
    asyncio.run(main())
