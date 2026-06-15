# Demo video script - target 2:35, hard cap 3:00

Record at 1080p with terminal text at least 16 pt. The final video must be
publicly accessible on YouTube, Vimeo, or Youku and contain only licensed assets.

## Shot list

**0:00-0:18 - Problem and hook**

> "Tier-1 SOC triage is repetitive but high-stakes: determine whether access
> succeeded, scope what happened next, and preserve the evidence. Sockeye is an
> autonomous analyst built on the official Splunk MCP Server. It investigates a
> live incident and records every query behind its verdict."

**0:18-0:42 - Live data in Splunk Web**

Show `http://localhost:8000` and run:

```spl
index=security dataset=sockeye-demo-v1
| dedup event_id
| stats count by sourcetype
```

> "This is Splunk Enterprise 10.4 with 1,976 unique events across 36 hours:
> normal authentication and network activity with a multi-stage intrusion buried
> inside. The agent knows the investigation method, not the planted answer."

**0:42-0:58 - Architecture and security**

Show `architecture.svg`.

> "Claude connects through Splunk MCP using a 30-day encrypted token for a
> dedicated role that can search only the security index. The agent receives one
> read-only Splunk query tool, and every exposed Docker port is loopback-only."

**0:58-1:55 - Run Sockeye**

```bash
.venv/bin/python agent/triage.py
```

Narrate the visible MCP calls:

> "It starts with event volume, then measures failures by source and account. It
> separates the distributed spray from 180 focused attempts against one service
> account. The key pivot is outcome: did an attempt succeed? It finds the login,
> follows the account to privilege escalation and a first-observed file-server
> login, then identifies staging and 570.9 megabytes transferred outbound."

Speed up quiet model time in editing. Keep at least two real tool calls legible.

**1:55-2:40 - Report and execution audit**

Open the generated report and show:

- confirmed-incident verdict and severity,
- ordered timeline,
- observed IOCs and affected systems,
- ranked containment actions, and
- the final Execution Audit with exact SPL copied from real tool calls.

> "The report separates observed facts from inference. More importantly, the
> runner appends the exact queries from the MCP session, so an analyst can rerun
> the evidence instead of trusting unsupported prose."

**2:40-2:55 - Close**

> "Sockeye turns raw Splunk events into a reviewable containment plan while
> preserving least privilege and an evidence trail. The complete MIT-licensed
> project and reproducible demo are on GitHub."

## Recording checklist

- [ ] Fresh deterministic dataset is present
- [ ] `python3 scripts/verify_mcp.py` passes
- [ ] A successful report is available as a backup
- [ ] Browser and terminal show no `.env`, tokens, credentials, or account email
- [ ] Video is under three minutes and publicly accessible
- [ ] Repository URL and project name are visible in the closing frame
