# SOC Triage Report - `index=security` 48-hour Sweep

> Representative output from the deterministic demo. Event timestamps vary with
> seed time; counts and the transfer total remain stable after deduplication.

## Verdict: CONFIRMED INCIDENT - Severity: Critical

The `svc-backup` account experienced 180 failed SSH logins from
`91.240.118.172`, followed by a successful login from the same source. The
account then performed successful privilege escalation, appeared on
`files01.sockeye.local`, staged `/srv/finance` and `/srv/hr`, and was associated
with 570,904,170 outbound bytes to the original external source. The sequence is
consistent with account compromise and data exfiltration.

A separate distributed password spray generated 220 failures across multiple
accounts. No successful login from those five spray sources was observed in the
search window.

## Timeline

| Relative phase | Observed evidence |
|---|---|
| T-6h | 220 distributed authentication failures across multiple accounts |
| T-3h | 180 focused failures for `svc-backup` from `91.240.118.172` |
| T-2h52m | Successful `svc-backup` login from the focused source |
| +3m | `sudo su -` completed with `result=success` |
| +6m40s | First-observed `svc-backup` login on `files01.sockeye.local` |
| +11m40s | Finance and HR directories archived to `/tmp/.cache.tgz` |
| +15m to +23m | 12 outbound flows totaling 570,904,170 bytes to `91.240.118.172:443` |

## IOCs

- `91.240.118.172`: observed brute-force source and later transfer destination
- `svc-backup`: compromised service account
- `dc01.sockeye.local`: initial access and privilege-escalation host
- `files01.sockeye.local`: collection and transfer host
- `/tmp/.cache.tgz`: staged archive path
- `185.220.101.12`, `.34`, `.57`, `.88`, `.144`: unsuccessful spray sources

The data establishes suspicious behavior for these values inside the demo. It
does not independently establish reputation, geolocation, or infrastructure
ownership.

## Evidence

**Authentication outcomes by source and user**

```spl
search index=security earliest=-48h latest=now sourcetype=auth:demo
| eval unique_event=coalesce(event_id, _cd)
| dedup unique_event
| stats count by src_ip, user, action
| sort 0 - count
```

Result: `91.240.118.172` produced 180 failures and one success for
`svc-backup`. The five distributed spray sources produced failures only.

**Post-access activity for the compromised account**

```spl
search index=security earliest=-48h latest=now user="svc-backup"
| eval unique_event=coalesce(event_id, _cd)
| dedup unique_event
| table _time, host, sourcetype, action, src_ip, dest, command, result, note
| sort 0 _time
```

Result: successful access was followed by privilege escalation, a login on the
file server, and archive creation.

**Outbound transfer to the original source**

```spl
search index=security earliest=-48h latest=now sourcetype=network:demo dest_ip="91.240.118.172"
| eval unique_event=coalesce(event_id, _cd)
| dedup unique_event
| stats count as flows, sum(bytes_out) as bytes_out by src_ip, dest_ip, dest_port
```

Result: 12 flows from `10.20.1.5` to `91.240.118.172:443`, totaling
570,904,170 bytes.

## Recommended actions

1. Block `91.240.118.172` at network controls and hunt for other communication
   with that address.
2. Isolate `files01.sockeye.local` and the initial-access host while preserving
   volatile and disk evidence.
3. Disable `svc-backup`, rotate its password and SSH keys, and identify every
   system where the credentials were authorized.
4. Determine exactly which Finance and HR records were present in the staged
   archive and begin the appropriate incident and legal review.
5. Review privilege-escalation, account, persistence, and scheduled-task changes
   on affected systems.
6. Add detections for focused authentication failures, service-account
   escalation, first-observed service-account logins, and outbound byte anomalies.

---

## Execution Audit

The live runner generates this section from actual MCP tool inputs. It is not
model-authored and contains the exact SPL submitted during that run.
