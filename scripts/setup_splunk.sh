#!/usr/bin/env bash
# One-shot Splunk configuration for Sockeye.
# Prereqs: container from docker/docker-compose.yml is up and healthy, and the
# official Splunk MCP Server app (.tgz from https://splunkbase.splunk.com/app/7931)
# is placed in docker/apps/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
source "$HERE/.env"

MGMT=${SPLUNK_MGMT_URL:-https://localhost:8089}
AUTH="admin:${SPLUNK_PASSWORD}"
CURL=(curl -ks -u "$AUTH")

echo "==> Waiting for Splunk management API..."
for i in $(seq 1 60); do
  "${CURL[@]}" "$MGMT/services/server/info?output_mode=json" >/dev/null 2>&1 && break
  sleep 5
done
"${CURL[@]}" "$MGMT/services/server/info?output_mode=json" \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['entry'][0]['content']; print('    Splunk', d['version'], 'on', d['serverName'])"

echo "==> Creating 'security' index..."
"${CURL[@]}" "$MGMT/services/data/indexes" -d name=security -d datatype=event >/dev/null \
  || echo "    (already exists)"

echo "==> Enabling token authentication..."
"${CURL[@]}" "$MGMT/services/admin/Token-auth/tokens_auth" -d disabled=false >/dev/null

echo "==> Granting MCP capabilities to the admin role..."
for cap in mcp_tool_execute mcp_tool_admin; do
  "${CURL[@]}" "$MGMT/services/authorization/roles/admin" -d "imported_capabilities=$cap" >/dev/null 2>&1 \
    || echo "    note: capability $cap not present yet (app not installed?) — rerun after install"
done

APP_PKG=$(ls "$HERE"/docker/apps/*.tgz "$HERE"/docker/apps/*.spl 2>/dev/null | head -1 || true)
if [ -n "$APP_PKG" ]; then
  echo "==> Installing MCP Server app: $(basename "$APP_PKG")"
  docker cp "$APP_PKG" sockeye-splunk:/tmp/mcp-app.pkg
  "${CURL[@]}" "$MGMT/services/apps/local" \
    -d filename=true -d name=/tmp/mcp-app.pkg -d update=true >/dev/null
  echo "==> Restarting Splunk to activate the app..."
  "${CURL[@]}" "$MGMT/services/server/control/restart" -X POST >/dev/null
  sleep 20
  for i in $(seq 1 60); do
    "${CURL[@]}" "$MGMT/services/server/info?output_mode=json" >/dev/null 2>&1 && break
    sleep 5
  done
  # capabilities only exist after the app is active
  for cap in mcp_tool_execute mcp_tool_admin; do
    "${CURL[@]}" "$MGMT/services/authorization/roles/admin" -d "imported_capabilities=$cap" >/dev/null
  done
else
  echo "!! No MCP app package found in docker/apps/ — download it from"
  echo "   https://splunkbase.splunk.com/app/7931 and rerun this script."
fi

echo "==> Creating bearer token for the MCP endpoint..."
TOKEN=$("${CURL[@]}" "$MGMT/services/authorization/tokens?output_mode=json" \
  -d name=admin -d audience=sockeye-mcp \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['entry'][0]['content']['token'])")

if grep -q '^SPLUNK_MCP_TOKEN=' "$HERE/.env"; then
  sed -i "s|^SPLUNK_MCP_TOKEN=.*|SPLUNK_MCP_TOKEN=$TOKEN|" "$HERE/.env"
else
  echo "SPLUNK_MCP_TOKEN=$TOKEN" >> "$HERE/.env"
fi
echo "    token written to .env (SPLUNK_MCP_TOKEN)"

echo "==> Verifying MCP endpoint..."
CODE=$(curl -ks -o /dev/null -w '%{http_code}' "$MGMT/services/mcp" \
  -H "Authorization: Bearer $TOKEN" -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sockeye-setup","version":"0.1"}}}')
echo "    POST /services/mcp -> HTTP $CODE"
[ "$CODE" = "200" ] && echo "==> Done. Splunk MCP server is live." \
  || echo "!! MCP endpoint not answering 200 yet — check that the app is installed and enabled."
