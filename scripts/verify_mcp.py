#!/usr/bin/env python3
"""Verify authentication and required tools on a Splunk MCP endpoint."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED_TOOLS = {
    "splunk_run_query",
}


def load_env(path: pathlib.Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def ssl_context(url: str, insecure_local_tls: bool) -> ssl.SSLContext | None:
    parsed = urlparse(url)
    if parsed.scheme == "http":
        if not is_loopback(parsed.hostname):
            raise ValueError("unencrypted MCP URLs are allowed only on loopback")
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("MCP URL must be an absolute HTTP(S) URL")
    if insecure_local_tls:
        if not is_loopback(parsed.hostname):
            raise ValueError("--insecure-local-tls requires a loopback MCP URL")
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=os.getenv("SPLUNK_CA_CERT") or None)


def rpc(
    url: str,
    token: str,
    method: str,
    request_id: int,
    context: ssl.SSLContext | None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
            or (
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "sockeye-verifier", "version": "1.0"},
                }
                if method == "initialize"
                else {}
            ),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": "sockeye-verifier/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MCP returned HTTP {exc.code}: {detail[:500]}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"MCP request failed: {exc}") from exc

    if body.startswith("event:") or body.startswith("data:"):
        data_lines = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
        body = "\n".join(data_lines)
    result = json.loads(body)
    if result.get("error"):
        raise RuntimeError(f"MCP {method} failed: {result['error']}")
    return result


def main(argv: list[str] | None = None) -> int:
    load_env(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("SPLUNK_MCP_URL"))
    parser.add_argument("--insecure-local-tls", action="store_true")
    args = parser.parse_args(argv)

    token = os.getenv("SPLUNK_MCP_TOKEN")
    if not args.url or not token:
        print("SPLUNK_MCP_URL and SPLUNK_MCP_TOKEN are required", file=sys.stderr)
        return 1
    try:
        context = ssl_context(args.url, args.insecure_local_tls)
        initialized = rpc(args.url, token, "initialize", 1, context)
        listed = rpc(args.url, token, "tools/list", 2, context)
        tools = {tool["name"] for tool in listed.get("result", {}).get("tools", [])}
        missing = REQUIRED_TOOLS - tools
        if missing:
            discovered = ", ".join(sorted(tools)) or "none"
            raise RuntimeError(
                f"required tools are missing: {', '.join(sorted(missing))}; "
                f"discovered: {discovered}"
            )
        called = rpc(
            args.url,
            token,
            "tools/call",
            3,
            context,
            {
                "name": "splunk_run_query",
                "arguments": {
                    "query": "search index=security | stats count",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 1,
                },
            },
        )
        if called.get("result", {}).get("isError"):
            raise RuntimeError(f"MCP query smoke test failed: {called['result']}")
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"MCP verification failed: {exc}", file=sys.stderr)
        return 1

    server = initialized.get("result", {}).get("serverInfo", {})
    print(f"connected to {server.get('name', 'Splunk MCP')} {server.get('version', '')}")
    print(f"required tools present: {', '.join(sorted(REQUIRED_TOOLS))}")
    print("query execution verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
