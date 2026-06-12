#!/usr/bin/env python3
"""Seed the local Splunk with a synthetic security incident.

Generates ~36h of auth + network logs into index=security via HEC:
  - baseline: normal logins for ~14 staff accounts from office IPs
  - attack:   password spray from 185.220.101.0/24 against many accounts,
              brute force against 'svc-backup', a SUCCESSFUL login from the
              attacker IP, privilege escalation, and a large outbound transfer.

The point is to give the triage agent a real trail to follow.
"""
import json
import os
import random
import ssl
import sys
import time
import urllib.request

random.seed(1337)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN")
if not HEC_TOKEN:
    sys.exit("SPLUNK_HEC_TOKEN not set (source .env first)")

NOW = time.time()
H = 3600

STAFF = ["aisha.bello", "tunde.okafor", "mary.eze", "john.adeyemi", "fatima.sani",
         "peter.obi", "grace.nwosu", "david.musa", "linda.ojo", "sam.ibrahim",
         "ruth.danjuma", "kemi.alabi", "emeka.uche", "zainab.lawal"]
OFFICE_IPS = [f"10.20.{i}.{random.randint(2, 250)}" for i in range(1, 8)]
ATTACKER_SPRAY = [f"185.220.101.{i}" for i in (12, 34, 57, 88, 144)]
ATTACKER_MAIN = "91.240.118.172"
TARGET = "svc-backup"
DC = "dc01.sockeye.local"
FILESRV = "files01.sockeye.local"

events = []

def ev(t, sourcetype, host, **fields):
    events.append({
        "time": round(t, 3),
        "event": fields,
        "sourcetype": sourcetype,
        "host": host,
        "index": "security",
    })

# --- baseline: normal business logins over 36h ---
for _ in range(900):
    t = NOW - random.uniform(0, 36 * H)
    user = random.choice(STAFF)
    ev(t, "auth:demo", DC, action="success", user=user,
       src_ip=random.choice(OFFICE_IPS), dest=DC, app="sshd",
       signature="Accepted password")
for _ in range(60):  # ordinary typos
    t = NOW - random.uniform(0, 36 * H)
    user = random.choice(STAFF)
    ev(t, "auth:demo", DC, action="failure", user=user,
       src_ip=random.choice(OFFICE_IPS), dest=DC, app="sshd",
       signature="Failed password")

# --- phase 1: password spray, ~6h ago, low-and-slow across accounts ---
t0 = NOW - 6 * H
for i in range(220):
    t = t0 + i * random.uniform(8, 30)
    ev(t, "auth:demo", DC, action="failure",
       user=random.choice(STAFF + [TARGET, "administrator", "root", "test"]),
       src_ip=random.choice(ATTACKER_SPRAY), dest=DC, app="sshd",
       signature="Failed password")

# --- phase 2: focused brute force on svc-backup, ~3h ago ---
t1 = NOW - 3 * H
for i in range(180):
    t = t1 + i * random.uniform(1, 4)
    ev(t, "auth:demo", DC, action="failure", user=TARGET,
       src_ip=ATTACKER_MAIN, dest=DC, app="sshd", signature="Failed password")

# --- phase 3: breach — successful login, ~2.5h ago ---
t2 = t1 + 0.45 * H
ev(t2, "auth:demo", DC, action="success", user=TARGET,
   src_ip=ATTACKER_MAIN, dest=DC, app="sshd", signature="Accepted password")

# --- phase 4: privilege escalation + lateral movement ---
ev(t2 + 180, "audit:demo", DC, action="priv_escalation", user=TARGET,
   src_ip=ATTACKER_MAIN, command="sudo su -", result="success")
ev(t2 + 400, "auth:demo", FILESRV, action="success", user=TARGET,
   src_ip="10.20.1.5", dest=FILESRV, app="sshd",
   signature="Accepted publickey", note="first ever login of this account here")

# --- phase 5: staging + exfil ---
ev(t2 + 700, "audit:demo", FILESRV, action="file_access", user=TARGET,
   command="tar czf /tmp/.cache.tgz /srv/finance /srv/hr", result="success")
for i in range(12):
    ev(t2 + 900 + i * 45, "network:demo", FILESRV, action="allowed",
       src_ip="10.20.1.5", dest_ip=ATTACKER_MAIN, dest_port=443,
       bytes_out=random.randint(38_000_000, 62_000_000), app="ssl")

# --- routine network noise ---
for _ in range(600):
    t = NOW - random.uniform(0, 36 * H)
    ev(t, "network:demo", FILESRV, action="allowed",
       src_ip=random.choice(OFFICE_IPS),
       dest_ip=f"104.18.{random.randint(0,255)}.{random.randint(1,254)}",
       dest_port=random.choice([443, 443, 443, 80, 53]),
       bytes_out=random.randint(2_000, 900_000), app="ssl")

events.sort(key=lambda e: e["time"])
print(f"sending {len(events)} events to {HEC_URL} ...")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BATCH = 200
for i in range(0, len(events), BATCH):
    payload = "\n".join(json.dumps(e) for e in events[i:i + BATCH]).encode()
    req = urllib.request.Request(
        HEC_URL, data=payload,
        headers={"Authorization": f"Splunk {HEC_TOKEN}"})
    with urllib.request.urlopen(req, context=ctx) as r:
        body = json.loads(r.read())
        if body.get("code") != 0:
            sys.exit(f"HEC error at batch {i}: {body}")
print("done. search with: index=security | stats count by sourcetype")
