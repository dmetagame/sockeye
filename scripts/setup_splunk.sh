#!/usr/bin/env bash
# Configure the local Sockeye Splunk demo and mint a least-privilege MCP token.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"
CONTAINER=${SPLUNK_CONTAINER:-sockeye-splunk}
AGENT_USER=${SPLUNK_MCP_USERNAME:-sockeye-agent}
AGENT_ROLE=sockeye_agent

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need docker
need python3
[ -f "$ENV_FILE" ] || die "Missing .env. Copy .env.example to .env first."

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
: "${SPLUNK_PASSWORD:?set SPLUNK_PASSWORD in .env}"
: "${SPLUNK_HEC_TOKEN:?set SPLUNK_HEC_TOKEN in .env}"
[[ "$AGENT_USER" =~ ^[A-Za-z0-9_.-]+$ ]] || die "Invalid SPLUNK_MCP_USERNAME"

AUTH="admin:${SPLUNK_PASSWORD}"

detect_management_url() {
  local candidate
  for candidate in https://127.0.0.1:8089 http://127.0.0.1:8089; do
    if curl --insecure --silent --show-error --fail --max-time 4 \
      --user "$AUTH" "$candidate/services/server/info?output_mode=json" \
      >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

wait_for_management() {
  local url=$1
  local curl_args=(--silent --show-error --fail --max-time 5 --user "$AUTH")
  [[ "$url" == https://* ]] && curl_args+=(--insecure)
  for _ in $(seq 1 90); do
    if curl "${curl_args[@]}" "$url/services/server/info?output_mode=json" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

echo "==> Waiting for Splunk management API..."
BOOT_URL=""
for _ in $(seq 1 90); do
  BOOT_URL=$(detect_management_url || true)
  [ -n "$BOOT_URL" ] && break
  sleep 2
done
[ -n "$BOOT_URL" ] || die "Splunk management API did not become ready"

BOOT_CURL=(curl --silent --show-error --fail --max-time 30 --user "$AUTH")
[[ "$BOOT_URL" == https://* ]] && BOOT_CURL+=(--insecure)
"${BOOT_CURL[@]}" "$BOOT_URL/services/server/info?output_mode=json" \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['entry'][0]['content']; print('    Splunk', d['version'], 'on', d['serverName'])"

echo "==> Ensuring index=security exists..."
if ! "${BOOT_CURL[@]}" "$BOOT_URL/services/data/indexes/security?output_mode=json" \
  >/dev/null 2>&1; then
  "${BOOT_CURL[@]}" "$BOOT_URL/services/data/indexes" \
    --data-urlencode name=security --data-urlencode datatype=event >/dev/null
fi

mapfile -t APP_PACKAGES < <(
  find "$ROOT/docker/apps" -maxdepth 1 -type f \( -name '*.tgz' -o -name '*.spl' \) -print | sort
)
[ "${#APP_PACKAGES[@]}" -eq 1 ] || die "Place exactly one Splunk MCP app package in docker/apps/"
APP_PACKAGE=${APP_PACKAGES[0]}

echo "==> Installing $(basename "$APP_PACKAGE")..."
docker cp "$APP_PACKAGE" "$CONTAINER:/tmp/sockeye-mcp-app.pkg" >/dev/null
"${BOOT_CURL[@]}" "$BOOT_URL/services/apps/local" \
  --data-urlencode filename=true \
  --data-urlencode name=/tmp/sockeye-mcp-app.pkg \
  --data-urlencode update=true >/dev/null

echo "==> Installing isolated Sockeye RBAC and loopback transport config..."
docker exec -u root "$CONTAINER" sh -c '
  install -d -o splunk -g splunk /opt/splunk/etc/apps/sockeye_demo/default
  install -d -o splunk -g splunk /opt/splunk/etc/apps/sockeye_demo/local
  cat > /opt/splunk/etc/apps/sockeye_demo/default/app.conf <<"CONF"
[install]
is_configured = 1
[ui]
is_visible = 0
CONF
  cat > /opt/splunk/etc/apps/sockeye_demo/local/authorize.conf <<"CONF"
[tokens_auth]
disabled = 0

[role_sockeye_agent]
search = enabled
mcp_tool_execute = enabled
srchIndexesAllowed = security
srchIndexesDefault = security
srchFilter = index=security
CONF
  cat > /opt/splunk/etc/apps/sockeye_demo/local/server.conf <<"CONF"
[sslConfig]
enableSplunkdSSL = false
CONF
  chown -R splunk:splunk /opt/splunk/etc/apps/sockeye_demo
'

echo "==> Restarting Splunk..."
"${BOOT_CURL[@]}" --request POST "$BOOT_URL/services/server/control/restart" >/dev/null
sleep 5
MGMT_URL=http://127.0.0.1:8089
wait_for_management "$MGMT_URL" || die "Splunk did not return on $MGMT_URL"
API=(
  curl --silent --show-error --fail --max-time 30
  --retry 12 --retry-all-errors --retry-delay 2
  --user "$AUTH"
)

echo "==> Ensuring dedicated MCP user exists..."
AGENT_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
if "${API[@]}" "$MGMT_URL/services/authentication/users/$AGENT_USER?output_mode=json" \
  >/dev/null 2>&1; then
  "${API[@]}" "$MGMT_URL/services/authentication/users/$AGENT_USER" \
    --data-urlencode roles="$AGENT_ROLE" >/dev/null
else
  "${API[@]}" "$MGMT_URL/services/authentication/users" \
    --data-urlencode name="$AGENT_USER" \
    --data-urlencode password="$AGENT_PASSWORD" \
    --data-urlencode roles="$AGENT_ROLE" >/dev/null
fi
unset AGENT_PASSWORD

echo "==> Minting a 30-day encrypted MCP token for $AGENT_USER..."
TOKEN=""
for _ in $(seq 1 12); do
  TOKEN=$("${API[@]}" \
    "$MGMT_URL/services/mcp_token?username=$AGENT_USER&expires_on=%2B30d" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" \
    2>/dev/null || true)
  [ -n "$TOKEN" ] && break
  sleep 2
done
[ -n "$TOKEN" ] || die "MCP token minting failed"

MCP_URL=http://127.0.0.1:8089/services/mcp
TOKEN="$TOKEN" MCP_URL="$MCP_URL" ENV_FILE="$ENV_FILE" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["ENV_FILE"])
updates = {
    "SPLUNK_MCP_URL": os.environ["MCP_URL"],
    "SPLUNK_MCP_TOKEN": os.environ["TOKEN"],
}
lines = path.read_text(encoding="utf-8").splitlines()
seen = set()
output = []
for line in lines:
    key = line.split("=", 1)[0].strip() if "=" in line else ""
    if key in updates:
        output.append(f"{key}={updates[key]}")
        seen.add(key)
    else:
        output.append(line)
for key, value in updates.items():
    if key not in seen:
        output.append(f"{key}={value}")
path.write_text("\n".join(output) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

echo "==> Verifying MCP authentication and required tools..."
SPLUNK_MCP_URL="$MCP_URL" SPLUNK_MCP_TOKEN="$TOKEN" \
  python3 "$ROOT/scripts/verify_mcp.py"

echo "==> Done. Token saved to .env; Splunk management is loopback-only HTTP."
