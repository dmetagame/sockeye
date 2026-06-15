#!/usr/bin/env python3
"""Seed Splunk HEC with a deterministic synthetic security incident."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATASET = "sockeye-demo-v1"
DEFAULT_HEC_URL = "https://localhost:8088/services/collector/event"
RANDOM_SEED = 1337
HOUR = 3600

STAFF = [
    "aisha.bello",
    "tunde.okafor",
    "mary.eze",
    "john.adeyemi",
    "fatima.sani",
    "chidi.adeleke",
    "grace.nwosu",
    "david.musa",
    "linda.ojo",
    "sam.ibrahim",
    "ruth.danjuma",
    "kemi.alabi",
    "emeka.uche",
    "zainab.lawal",
]
ATTACKER_SPRAY = [f"185.220.101.{value}" for value in (12, 34, 57, 88, 144)]
ATTACKER_MAIN = "91.240.118.172"
TARGET = "svc-backup"
DC = "dc01.sockeye.local"
FILE_SERVER = "files01.sockeye.local"


def load_env(path: pathlib.Path) -> None:
    """Load the simple KEY=VALUE file used by this demo without extra dependencies."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Build but do not send")
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def tls_context(url: str) -> ssl.SSLContext | None:
    parsed = urlparse(url)
    if parsed.scheme == "http":
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("SPLUNK_HEC_URL must be an absolute HTTP(S) URL")

    verify_setting = os.getenv("SPLUNK_HEC_VERIFY_TLS")
    verify = not is_loopback(parsed.hostname)
    if verify_setting is not None:
        verify = verify_setting.strip().lower() not in {"0", "false", "no", "off"}

    ca_file = os.getenv("SPLUNK_CA_CERT")
    if verify:
        return ssl.create_default_context(cafile=ca_file or None)

    if not is_loopback(parsed.hostname):
        print(
            "WARNING: TLS verification is disabled for a non-loopback HEC endpoint.",
            file=sys.stderr,
        )
    return ssl._create_unverified_context()


def build_events(now: float) -> list[dict[str, Any]]:
    rng = random.Random(RANDOM_SEED)
    office_ips = [f"10.20.{i}.{rng.randint(2, 250)}" for i in range(1, 8)]
    events: list[dict[str, Any]] = []

    def add(event_id: str, timestamp: float, sourcetype: str, host: str, **fields: Any) -> None:
        event = {"dataset": DATASET, "event_id": event_id, **fields}
        events.append(
            {
                "time": round(timestamp, 3),
                "event": event,
                "sourcetype": sourcetype,
                "host": host,
                "index": "security",
            }
        )

    for number in range(900):
        add(
            f"baseline-success-{number:04d}",
            now - rng.uniform(0, 36 * HOUR),
            "auth:demo",
            DC,
            action="success",
            user=rng.choice(STAFF),
            src_ip=rng.choice(office_ips),
            dest=DC,
            app="sshd",
            signature="Accepted password",
        )
    for number in range(60):
        add(
            f"baseline-failure-{number:04d}",
            now - rng.uniform(0, 36 * HOUR),
            "auth:demo",
            DC,
            action="failure",
            user=rng.choice(STAFF),
            src_ip=rng.choice(office_ips),
            dest=DC,
            app="sshd",
            signature="Failed password",
        )

    spray_time = now - 6 * HOUR
    spray_targets = STAFF + [TARGET, "administrator", "root", "test"]
    for number in range(220):
        spray_time += rng.uniform(8, 30)
        add(
            f"spray-{number:04d}",
            spray_time,
            "auth:demo",
            DC,
            action="failure",
            user=rng.choice(spray_targets),
            src_ip=rng.choice(ATTACKER_SPRAY),
            dest=DC,
            app="sshd",
            signature="Failed password",
        )

    brute_time = now - 3 * HOUR
    for number in range(180):
        brute_time += rng.uniform(1, 4)
        add(
            f"brute-force-{number:04d}",
            brute_time,
            "auth:demo",
            DC,
            action="failure",
            user=TARGET,
            src_ip=ATTACKER_MAIN,
            dest=DC,
            app="sshd",
            signature="Failed password",
        )

    breach_time = brute_time + 60
    add(
        "initial-access",
        breach_time,
        "auth:demo",
        DC,
        action="success",
        user=TARGET,
        src_ip=ATTACKER_MAIN,
        dest=DC,
        app="sshd",
        signature="Accepted password",
    )
    add(
        "privilege-escalation",
        breach_time + 180,
        "audit:demo",
        DC,
        action="priv_escalation",
        user=TARGET,
        src_ip=ATTACKER_MAIN,
        command="sudo su -",
        result="success",
    )
    add(
        "lateral-movement",
        breach_time + 400,
        "auth:demo",
        FILE_SERVER,
        action="success",
        user=TARGET,
        src_ip="10.20.1.5",
        dest=FILE_SERVER,
        app="sshd",
        signature="Accepted publickey",
        note="first observed login of this account on this host",
    )
    add(
        "collection-staging",
        breach_time + 700,
        "audit:demo",
        FILE_SERVER,
        action="file_access",
        user=TARGET,
        command="tar czf /tmp/.cache.tgz /srv/finance /srv/hr",
        result="success",
    )
    for number in range(12):
        add(
            f"exfiltration-{number:02d}",
            breach_time + 900 + number * 45,
            "network:demo",
            FILE_SERVER,
            action="allowed",
            src_ip="10.20.1.5",
            dest_ip=ATTACKER_MAIN,
            dest_port=443,
            bytes_out=rng.randint(38_000_000, 62_000_000),
            app="ssl",
        )

    for number in range(600):
        add(
            f"network-baseline-{number:04d}",
            now - rng.uniform(0, 36 * HOUR),
            "network:demo",
            FILE_SERVER,
            action="allowed",
            src_ip=rng.choice(office_ips),
            dest_ip=f"104.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            dest_port=rng.choice([443, 443, 443, 80, 53]),
            bytes_out=rng.randint(2_000, 900_000),
            app="ssl",
        )

    events.sort(key=lambda event: event["time"])
    return events


def send_events(
    events: list[dict[str, Any]],
    url: str,
    token: str,
    batch_size: int,
    timeout: float,
) -> None:
    context = tls_context(url)
    for offset in range(0, len(events), batch_size):
        batch = events[offset : offset + batch_size]
        payload = "\n".join(json.dumps(event, separators=(",", ":")) for event in batch)
        request = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
                "User-Agent": "sockeye-seeder/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
                body = json.loads(response.read())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"HEC request failed at event {offset}: {exc}") from exc
        if body.get("code") != 0:
            raise RuntimeError(f"HEC rejected batch at event {offset}: {body}")


def main(argv: list[str] | None = None) -> int:
    load_env(ROOT / ".env")
    args = parse_args(argv)
    if args.batch_size < 1 or args.batch_size > 1000:
        print("--batch-size must be between 1 and 1000", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("--timeout must be positive", file=sys.stderr)
        return 2

    events = build_events(time.time())
    print(f"built {len(events)} deterministic events for dataset={DATASET}")
    print("event_id values are stable; Sockeye deduplicates repeated demo ingests")
    if args.dry_run:
        return 0

    token = os.getenv("SPLUNK_HEC_TOKEN")
    if not token:
        print("SPLUNK_HEC_TOKEN is not set", file=sys.stderr)
        return 1
    url = os.getenv("SPLUNK_HEC_URL", DEFAULT_HEC_URL)
    try:
        send_events(events, url, token, args.batch_size, args.timeout)
    except (RuntimeError, ValueError) as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1
    print("done. Search: index=security dataset=sockeye-demo-v1 | stats count by sourcetype")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
