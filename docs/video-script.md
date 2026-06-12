# Demo video script — target 2:30, hard cap 3:00

Record at 1080p. Terminal font ≥16pt. One take is fine; cut dead air.
OBS/ScreenToGif/Clipchamp all work. Upload to YouTube as **Unlisted is NOT
allowed by some hackathons — use Public** for Devpost safety.

## Shot list

**[0:00–0:20] Hook (talking over README or title slide)**
> "Tier-1 SOC triage is hours of staring at auth logs. Sockeye is an
> autonomous analyst built on the official Splunk MCP Server: it doesn't
> summarize alerts — it investigates them. Watch it work a real incident,
> end to end, in one command."

**[0:20–0:45] The setup (30s, screen: Splunk Web at http://localhost:8000)**
- Show `index=security` in Search: `index=security | stats count by sourcetype`
- Say: "A live Splunk Enterprise instance with 2,000 events — 36 hours of
  normal logins for 14 staff... and an attack buried inside. Sockeye doesn't
  know what's planted. It only knows the method: sweep, pivot, quantify."

**[0:45–0:55] The wiring (10s, screen: README architecture diagram)**
> "Claude connects through the official Splunk MCP Server app — streamable
> HTTP on the management port, RSA-encrypted bearer token, rate-limited and
> guardrailed server-side. The agent is 100 lines of Python on the Claude
> Agent SDK."

**[0:55–2:05] The run (70s, screen: terminal)**
```bash
set -a; source .env; set +a
.venv/bin/python agent/triage.py
```
- Narrate the tool calls as they scroll (speed up 2–4× in editing if needed):
  "Broad sweep first... it spots two clusters of failures: a slow spray from
  Tor exits, and 180 attempts in 11 minutes against one service account...
  now the pivot that matters — did any attempt SUCCEED? One did. 11:46 AM,
  svc-backup, from the brute-force IP... it follows the account: sudo to
  root on the domain controller, lateral move to the file server, a hidden
  tar of finance and HR shares... and 571 megabytes out to the attacker over
  443."

**[2:05–2:45] The report (40s, screen: reports/triage-*.md rendered)**
- Scroll slowly through: Verdict (CONFIRMED INCIDENT — CRITICAL), timeline
  table, IOCs, evidence section, ranked actions.
> "Every claim cites the SPL it ran — an auditable evidence chain, not
> vibes. It even flagged that the spray had zero successes, so it triaged
> that as contained recon instead of crying wolf. And because the foothold
> was a domain controller, action #3 is a KRBTGT reset."

**[2:45–3:00] Close (title slide / repo)**
> "Sockeye: agentic SOC triage on the official Splunk MCP Server. One
> command from raw logs to containment plan. Repo's open source — MIT."

## Checklist before recording
- [ ] `docker ps` → sockeye-splunk healthy
- [ ] Fresh terminal, big font, dark theme
- [ ] `reports/` has the previous run handy as backup if the live run is slow
- [ ] No secrets on screen (.env never opened on camera)
