# Devpost submission — copy/paste pack

**Project name:** Sockeye — Agentic SOC Triage on the Splunk MCP Server
**Track:** Security
**Opt-in categories:** Best Use of MCP Server
**Repo:** https://github.com/dmetagame/sockeye
**Elevator:** An autonomous SOC analyst that investigates — not summarizes —
security incidents in Splunk, using the official Splunk MCP Server as its hands.

---

## Inspiration

Tier-1 triage is the highest-volume, most repetitive job in every SOC: stare at
a wall of auth failures, decide what's noise, chase what isn't. Most "AI for
security" demos stop at summarizing alerts. We wanted an agent that does the
actual analyst work — forms hypotheses, runs SPL, pivots on what it finds, and
hands a human a containment plan with the evidence attached.

## What it does

Sockeye connects Claude to a live Splunk Enterprise instance through the
**official Splunk MCP Server** (Splunkbase 7931). On every run it:

1. sweeps `index=security` broadly (volume by sourcetype, failures by src_ip/user),
2. pivots like an analyst — "this IP brute-forced one account; did it ever
   *succeed*? what did the account do next?",
3. quantifies everything with SPL it writes itself through MCP tools, and
4. emits a markdown triage report: verdict + severity, attack timeline, IOCs,
   the exact queries behind every claim, and ranked containment actions.

In our live run it independently reconstructed a 5-phase intrusion (Tor
password spray → brute force on `svc-backup` → successful login → `sudo su -`
escalation → lateral move → 571 MB exfil over 443) from ~2,000 events, in 10
agent turns — and correctly classified the spray as contained recon because it
verified zero successes.

## How we built it

- **Splunk Enterprise 10.4** in Docker (free trial), with the official
  **Splunk MCP Server app v1.2.0** exposing tools (`splunk_run_query`,
  index/metadata tools) at `/services/mcp` over MCP streamable HTTP with
  RSA-encrypted bearer tokens.
- **Claude Agent SDK (Python)** drives the agentic loop — ~100 lines, no
  framework. The MCP server is declared as an HTTP server in the agent
  options; the system prompt teaches *method* (sweep → pivot → quantify →
  report), never the answers.
- **Synthetic attack generator** (`scripts/seed_data.py`) ingests a realistic
  36-hour scenario via HEC: 14 staff accounts of benign baseline with an
  attack chain buried inside.
- **One-shot setup script** handles index creation, token auth, app install,
  RBAC capabilities, and MCP token minting.

## Challenges we ran into

- The MCP server rejects generic Splunk JWTs — it requires RSA-encrypted
  tokens with audience `mcp`, minted by the app's own `/services/mcp_token`
  endpoint. We read the app's handler source to find the contract.
- Splunk's role REST endpoint *replaces* a role's capability list on POST —
  we briefly stripped the admin role of every capability and had to restore
  it via `authorize.conf`. The setup script now does it the safe way.
- Splunk 10.4's Docker image added a second license-acceptance gate
  (`SPLUNK_GENERAL_TERMS`).

## Accomplishments we're proud of

- A real agent, not a wrapper: every report claim is backed by an SPL query
  the agent actually ran — auditable evidence chain, zero hallucinated IOCs.
- Full local reproducibility: `docker compose up` → setup script → seed →
  run. No cloud dependencies beyond the model.
- The agent caught the nuance: spray = recon (no successes), brute force =
  breach — and prioritized KRBTGT rotation because the foothold was a DC.

## What we learned

MCP is the right security boundary for agentic ops: the agent never holds
Splunk credentials beyond a scoped, expiring, RSA-encrypted token, and the
server enforces rate limits, row limits, and SPL guardrails on every call.

## What's next

- Continuous mode: run on a schedule, diff verdicts, page only on escalation
- Write-back: post triage reports to Splunk as events for dashboarding
- Multi-agent: parallel sub-investigations per IOC under a coordinator
