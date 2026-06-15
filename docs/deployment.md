# Web deployment

Sockeye includes a single-tenant FastAPI dashboard suitable for a hackathon demo
or an internal security tool. The web container runs the Claude Agent SDK; Splunk
and its official MCP Server remain a separate private service.

## Local Docker deployment

Complete the normal Splunk setup first so `.env` contains a scoped MCP token:

```bash
cp .env.example .env
# Set SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN, then add the MCP app package.
docker compose -f docker/docker-compose.yml --env-file .env up -d
./scripts/setup_splunk.sh
python3 scripts/seed_data.py
```

Set these additional values in `.env`:

```dotenv
ANTHROPIC_API_KEY=sk-ant-...
SOCKEYE_WEB_API_KEY=a-long-random-access-key
```

Start the web overlay:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.web.yml \
  --env-file .env \
  up -d --build web
```

Open `http://127.0.0.1:3000` and enter `SOCKEYE_WEB_API_KEY`. Reports and job
metadata persist in the `sockeye-data` Docker volume.

The local overlay explicitly permits HTTP only between `web` and `splunk` on
their private Docker network. That exception must not be copied to a deployment
where MCP traffic crosses hosts or an untrusted network.

## Hosted deployment

Deploy the root `Dockerfile` to a container platform such as Render, Fly.io,
Railway, ECS, Cloud Run with extended request timeouts, or Kubernetes.

Required environment variables:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API authentication for third-party hosting |
| `SPLUNK_MCP_URL` | Private HTTPS URL for the Splunk MCP endpoint |
| `SPLUNK_MCP_TOKEN` | Encrypted, expiring token for the scoped Sockeye user |
| `SOCKEYE_WEB_API_KEY` | Access key for the dashboard and API; minimum 24 characters |
| `SOCKEYE_STATE_DIR` | Writable persistent path, default `/data` |
| `SOCKEYE_FORWARDED_ALLOW_IPS` | Comma-separated trusted proxy IPs, default `127.0.0.1` |

Mount persistent storage at `/data`. The root filesystem can remain read-only;
the container needs only `/data` and `/tmp` writable.

## Network requirements

- Do not expose Splunk port `8089` directly to the public internet.
- Put the web service and Splunk on a private network, VPN, or private endpoint.
- Remote `SPLUNK_MCP_URL` values must use HTTPS with a trusted certificate.
- Terminate public TLS at the hosting platform or an authenticated reverse proxy.
- Set `SOCKEYE_FORWARDED_ALLOW_IPS` to only that proxy's source IPs; never use `*`
  when clients can reach the container directly.
- Keep the web service request timeout above the maximum investigation duration.

## API

- `POST /api/jobs`: start an investigation
- `GET /api/jobs`: list persisted jobs
- `GET /api/jobs/{id}`: inspect status
- `GET /api/jobs/{id}/events`: authenticated SSE progress stream
- `GET /api/jobs/{id}/report`: read or download markdown
- `GET /healthz`: liveness
- `GET /readyz`: configuration readiness

All `/api/jobs` routes require `Authorization: Bearer <SOCKEYE_WEB_API_KEY>` or
`X-API-Key`. The browser keeps the key in `sessionStorage`, so it is cleared when
the tab session ends.

## Operating limits

The current release intentionally runs one investigation at a time and allows a
maximum of five queued/running jobs. Configure `SOCKEYE_MAX_PENDING_JOBS` and
`SOCKEYE_MAX_JOB_HISTORY` as needed. For multi-tenant production use, replace the
in-process queue and access key with a durable worker queue, database, and your
identity provider.
