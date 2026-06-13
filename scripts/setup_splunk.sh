#!/usr/bin/env bash
# One-shot Splunk configuration for Sockeye.
# Prereqs: container from docker/docker-compose.yml is up, and the official
# Splunk MCP Server app (.tgz from https://splunkbase.splunk.com/app/7931)
# is placed in docker/apps/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
source "$HERE/.env"

MGMT=${SPLUNK_MGMT_URL:-https://localhost:8089}
AUTH="admin:${SPLUNK_PASSWORD}"
CURL=(curl -ks -u "$AUTH")

api_up() { "${CURL[@]}" --max-time 5 "$MGMT/services/server/info?output_mode=json" >/dev/null 2>&1; }

wait_up() {
  for _ in $(seq 1 90); do api_up && return 0; sleep 5; done
  echo "!! Splunk management API did not come up"; exit 1
}

echo "==> Waiting for Splunk management API..."
wait_up
"${CURL[@]}" "$MGMT/services/server/info?output_mode=json" \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['entry'][0]['content']; print('    Splunk', d['version'], 'on', d['serverName'])"

echo "==> Creating 'security' index..."
"${CURL[@]}" "$MGMT/services/data/indexes" -d name=security -d datatype=event >/dev/null \
  || echo "    (already exists)"

APP_PKG=$(ls "$HERE"/docker/apps/*.tgz "$HERE"/docker/apps/*.spl 2>/dev/null | head -1 || true)
if [ -z "$APP_PKG" ]; then
  echo "!! No MCP app package found in docker/apps/."
  echo "   Download it from https://splunkbase.splunk.com/app/7931 and rerun."
  exit 1
fi

echo "==> Installing MCP Server app: $(basename "$APP_PKG")"
docker cp "$APP_PKG" sockeye-splunk:/tmp/mcp-app.pkg
"${CURL[@]}" "$MGMT/services/apps/local" \
  -d filename=true -d name=/tmp/mcp-app.pkg -d update=true >/dev/null

echo "==> Enabling token auth + MCP capabilities (authorize.conf)..."
# NOTE: do NOT POST capabilities to /services/authorization/roles/<role> —
# that REPLACES the role's explicit capability list and strips admin rights.
docker exec -u root sockeye-splunk sh -c 'cat > /opt/splunk/etc/system/local/authorize.conf <<CONF
[tokens_auth]
disabled = 0

[role_admin]
mcp_tool_admin = enabled
mcp_tool_execute = enabled
CONF
chown splunk:splunk /opt/splunk/etc/system/local/authorize.conf'

echo "==> Restarting Splunk to activate app + capabilities..."
"${CURL[@]}" -X POST "$MGMT/services/server/control/restart" >/dev/null
echo "    waiting for splunkd to go down..."
for _ in $(seq 1 36); do api_up || break; sleep 5; done
api_up && { echo "!! splunkd never went down; restart with: docker restart sockeye-splunk"; exit 1; }
echo "    waiting for splunkd to come back..."
wait_up

echo "==> Minting encrypted MCP token (app endpoint /services/mcp_token)..."
# The MCP server only accepts RSA-encrypted tokens with audience 'mcp',
# minted by the app itself — generic Splunk JWTs are rejected.
TOKEN=""
for _ in $(seq 1 12); do
  TOKEN=$("${CURL[@]}" "$MGMT/services/mcp_token?username=admin&expires_on=%2B30d" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
  [ -n "$TOKEN" ] && break
  sleep 5
done
[ -z "$TOKEN" ] && { echo "!! token minting failed — check: docker logs sockeye-splunk"; exit 1; }

if grep -q '^SPLUNK_MCP_TOKEN=' "$HERE/.env"; then
  sed -i "s|^SPLUNK_MCP_TOKEN=.*|SPLUNK_MCP_TOKEN=$TOKEN|" "$HERE/.env"
else
  echo "SPLUNK_MCP_TOKEN=$TOKEN" >> "$HERE/.env"
fi
chmod 600 "$HERE/.env"
echo "    token written to .env (SPLUNK_MCP_TOKEN, expires +30d)"

echo "==> Verifying MCP endpoint..."
CODE=$(curl -ks -o /dev/null -w '%{http_code}' "$MGMT/services/mcp" \
  -H "Authorization: Bearer $TOKEN" -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sockeye-setup","version":"0.1"}}}')
echo "    POST /services/mcp -> HTTP $CODE"
[ "$CODE" = "200" ] && echo "==> Done. Splunk MCP server is live." \
  || { echo "!! MCP endpoint not answering 200 — check the app in Splunk Web > Apps."; exit 1; }
