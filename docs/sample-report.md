# SOC Triage Report — `index=security` 48h Sweep

**Analyst:** Sockeye · **Run time:** 2026-06-13 · **Window:** 2026-06-11 → 2026-06-13 (last 48h)

---

## Verdict: 🔴 CONFIRMED INCIDENT — **Severity: CRITICAL**

A service account (`svc-backup`) was compromised via SSH brute-force from a hostile external IP, escalated to root, moved laterally to the file server, archived Finance/HR data, and exfiltrated **~570 MB** back to the attacker. This is a complete, successful intrusion with confirmed data theft — not an attempt. A separate Tor-based password spray ran in parallel but **failed** (zero successes).

---

## Timeline of Attack Phases (all 2026-06-13)

| Time | Phase | Evidence |
|------|-------|----------|
| 08:13–09:25 | **Recon / spray (failed)** | Tor exit nodes `185.220.101.0/24` spray ~17 users incl. `svc-backup`, `administrator`, `root` against `dc01.sockeye.local` — all `failure` |
| 11:10:33–11:37 | **Brute-force (vertical)** | `91.240.118.172` hammers `svc-backup` on `dc01` — **180 failed** "Failed password" events in ~7 min |
| **11:37:33** | **Initial access** | `Accepted password` — `svc-backup` from `91.240.118.172` on `dc01.sockeye.local` |
| **11:40:33** | **Privilege escalation** | audit: `sudo su -` → `result: success`, user `svc-backup`, src `91.240.118.172` |
| **11:44:13** | **Lateral movement** | `svc-backup` SSH `Accepted publickey` from `10.20.1.5` → `files01.sockeye.local` (audit note: *"first ever login of this account here"*) |
| **11:49:13** | **Collection / staging** | audit `file_access`: `tar czf /tmp/.cache.tgz /srv/finance /srv/hr` → success |
| **11:52:33–12:00:48** | **Exfiltration** | 12 SSL flows `10.20.1.5 → 91.240.118.172:443`, **570,904,170 bytes (~570 MB)** total |

Dwell time from initial access to exfiltration: **~15 minutes** (highly automated).

---

## IOCs

**Attacker infrastructure**
- `91.240.118.172` — brute-force source + exfil destination (C2/drop). **Block immediately.**
- `185.220.101.12`, `.34`, `.57`, `.88`, `.144` — Tor exit nodes used for the (failed) spray.

**Compromised accounts**
- `svc-backup` — fully compromised; brute-forced, escalated to root, used for lateral movement + collection.

**Affected hosts**
- `dc01.sockeye.local` — initial foothold + priv-esc (domain controller).
- `files01.sockeye.local` — file server, data staged & stolen from `/srv/finance` and `/srv/hr`.
- `10.20.1.5` — internal pivot host that performed the lateral login and the exfil transfer.

**Artifacts**
- `/tmp/.cache.tgz` — staged exfil archive (Finance + HR data).

---

## Evidence — Key SPL Queries Run This Session

**1. Auth failures by source/user (48h)** — surfaced both attack patterns:
```spl
index=security (action=failure OR ...) | stats count as failures by src_ip, user | sort - failures
```
→ `91.240.118.172` / `svc-backup` = **180 failures** (vertical brute-force); `185.220.101.0/24` = low-count spray across ~17 users.

**2. Successes + brute-force outcome pivot:**
```spl
index=security (src_ip="91.240.118.172" OR src_ip="185.220.101.*") | stats count by src_ip, action, user
```
→ `91.240.118.172`: 180 `failure`, **1 `success`, 1 `priv_escalation`** on `svc-backup`. All `185.220.101.x` = `failure` only (**spray failed, 0 successes**).

**3. Outbound transfer volume:**
```spl
index=security sourcetype=network:demo | stats sum(bytes_out) as total_bytes_out, count by src_ip, dest_ip | sort - total_bytes_out
```
→ `10.20.1.5 → 91.240.118.172` = **570,904,170 bytes / 12 flows**. Next-highest pair ≈ 0.9 MB (normal baseline) — anomaly factor ~650×.

**4. Kill-chain reconstruction (auth + audit + network correlated):**
```spl
index=security (user=svc-backup AND (action=success OR action=priv_escalation))
  OR (src_ip=10.20.1.5 AND dest_ip=91.240.118.172) OR sourcetype=audit:demo
| table t, sourcetype, action, user, src_ip, dest, dest_ip, bytes_out, _raw | sort t
```
→ Produced the ordered timeline above: access (11:37) → `sudo su -` (11:40) → lateral login to files01 (11:44) → `tar` of /srv/finance & /srv/hr (11:49) → 570 MB exfil (11:52–12:00).

---

## Recommended Actions (ranked by urgency)

1. **CONTAIN NOW — block C2:** Block `91.240.118.172` inbound/outbound at perimeter firewall. Hunt for any other internal hosts talking to it.
2. **Isolate hosts:** Network-quarantine `files01.sockeye.local`, `10.20.1.5`, and `dc01.sockeye.local` for forensic imaging before reboot/cleanup.
3. **Disable & rotate `svc-backup`:** Lock the account immediately; rotate its credentials **and** revoke/rotate its SSH keys (lateral move used `Accepted publickey`). Audit where this key is authorized.
4. **Assume DC compromise:** `sudo su -` succeeded on a domain controller. Rotate `krbtgt` (twice), all domain admin and service-account credentials; review for new accounts, scheduled tasks, and persistence on `dc01`.
5. **Scope the breach:** Treat `/srv/finance` and `/srv/hr` as exfiltrated. Engage IR/legal for data-breach notification; identify exact records in the 570 MB archive. Recover/inspect `/tmp/.cache.tgz` on `files01`.
6. **Block Tor & harden auth:** Block `185.220.101.0/24` (and a current Tor exit list); enforce account lockout + MFA on SSH; remove password auth for service accounts (keys only) on internet-reachable hosts.
7. **Detections to deploy:** Alert on (a) >N auth failures per src_ip/user in 5 min, (b) any `priv_escalation`/`sudo su -` on service accounts, (c) outbound `bytes_out` anomalies to external IPs, (d) "first ever login" notes on service accounts.

*All findings above are backed by queries executed against `index=security` this session. The Tor spray was verified as unsuccessful and is reported as a failed attempt, not a breach.*