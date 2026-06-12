# Sockeye Triage Report — index=security (48h sweep)

**Run:** 2026-06-12 · Window: -48h → now (all times GMT)

## Verdict

**CONFIRMED INCIDENT — Severity: CRITICAL**

Successful brute-force compromise of service account `svc-backup` on domain controller `dc01.sockeye.local`, followed by root privilege escalation, lateral movement to `files01.sockeye.local`, staging of finance/HR data, and **~571 MB exfiltration to the attacker IP**. Attack is complete or in late stage — exfil ended ~12:09, roughly 1.5h before this sweep.

A separate Tor-based password spray earlier the same morning produced **zero successes** (suspicious, but contained — likely recon by the same actor).

## Timeline

| Time (GMT, 2026-06-12) | Phase | Detail |
|---|---|---|
| 08:19 – 10:00 | Recon / password spray | 5 IPs in 185.220.101.0/24 (known Tor exit range) → ~220 failures across 16–17 users incl. `administrator`, `root`, `test`. **No successes.** |
| 11:19 – 11:30 | Brute force | `91.240.118.172` → **180 failed logins**, all targeting `svc-backup` on `dc01`. |
| 11:46:03 | **Initial access** | `Accepted password` for `svc-backup` from `91.240.118.172` on `dc01.sockeye.local`. |
| 11:49:03 | Privilege escalation | `svc-backup` ran `sudo su -` on dc01 — **success** (audit:demo). |
| 11:52:43 | Lateral movement | SSH `Accepted publickey` as `svc-backup` from `10.20.1.5` (dc01) → `files01.sockeye.local`. |
| 11:57:43 | Collection / staging | On files01: `tar czf /tmp/.cache.tgz /srv/finance /srv/hr` — hidden-dotfile archive of sensitive shares. |
| 12:01 – 12:09 | **Exfiltration** | 12 connections, `10.20.1.5` → `91.240.118.172:443`, **570,904,170 bytes (~571 MB) out**. |

## IOCs

- **Attacker IP (active, exfil destination):** `91.240.118.172`
- **Spray IPs (Tor exits):** `185.220.101.12`, `.34`, `.57`, `.88`, `.144`
- **Compromised account:** `svc-backup` (also escalated to **root** on dc01)
- **Affected hosts:** `dc01.sockeye.local` (10.20.1.5 — domain controller, initial foothold + exfil source), `files01.sockeye.local` (data staging)
- **Staged artifact:** `/tmp/.cache.tgz` on files01 (contents of `/srv/finance`, `/srv/hr`)

## Evidence (queries run this session)

1. **Volume by sourcetype** — `index=security | stats count by sourcetype` → auth:demo 1,362 · network:demo 612 · audit:demo 2.
2. **Failures by src_ip** — `... action=failure | stats count dc(user) min/max(_time) by src_ip` → `91.240.118.172`: 180 fails / 1 user in 11 min (brute force); 185.220.101.x: 36–52 fails each across 16–17 users (spray). Internal 10.20.x sources: 6–14 fails each over 48h = normal noise.
3. **Failures by user** — `svc-backup`: 191 failures (dominant target); all other users ≤25.
4. **Success pivot** — `action=success (src_ip=91.240.118.172 OR 185.220.101.*)` → exactly **one** hit: svc-backup on dc01 at 11:46:03 from 91.240.118.172. Spray IPs: zero successes.
5. **Audit trail** — `sourcetype=audit:demo` → `priv_escalation` (`sudo su -`, success, 11:49) and `file_access` (tar of /srv/finance + /srv/hr, 11:57).
6. **Lateral movement** — `user=svc-backup action=success` → second success at 11:52:43, `Accepted publickey` from 10.20.1.5 → files01.
7. **Exfil** — `sourcetype=network:demo | stats sum(bytes_out) by src_ip dest_ip dest_port` → 10.20.1.5 → 91.240.118.172:443, 12 flows, 570.9 MB out (12:01–12:09). All other outbound flows ≤ ~0.9 MB (baseline browsing-scale traffic).

## Recommended actions (ranked)

1. **NOW — Block `91.240.118.172`** (and 185.220.101.0/24) at the perimeter, both directions. Exfil channel was live 90 min ago.
2. **NOW — Disable `svc-backup`** and kill all its active sessions on dc01 and files01. Rotate its credentials; it fell to an 11-minute online brute force — enforce a strong random secret and restrict to non-interactive use.
3. **NOW — Isolate `dc01.sockeye.local`.** Attacker had root on a domain controller: treat domain credential material (KRBTGT, AD secrets) as potentially compromised. Plan a double KRBTGT reset and domain-wide privileged credential rotation.
4. **Urgent — Forensics on files01:** preserve `/tmp/.cache.tgz`, check for the SSH key the attacker used for the publickey login (likely planted in `svc-backup`'s `authorized_keys` from dc01), and remove persistence.
5. **Urgent — Data-breach assessment:** ~571 MB of `/srv/finance` and `/srv/hr` content presumed exfiltrated — engage legal/compliance for notification obligations.
6. **Hardening:** enforce lockout/rate-limiting and MFA on external auth, disallow password auth for service accounts, alert on >20 auth failures per src_ip per 10 min, and alert on outbound transfers >50 MB to non-allowlisted IPs.