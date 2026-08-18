# Steward systemd deployment

This guide describes an evergreen source deployment of the Steward API and credential proxy on a
Linux host. For the supported Docker topology and complete environment reference, start with
[`README.md`](./README.md). Do not treat this page as an inventory or health report for any live
deployment.

## Prerequisites

- Bun 1.3 or newer
- PostgreSQL reachable from the host
- Redis for production rate limiting, replay protection, and distributed coordination
- A dedicated, unprivileged service account
- TLS termination and a firewall or private network in front of both services

## Install

Clone or synchronize the repository to a fixed application directory. The examples use
`/opt/steward`; adjust `STEWARD_DIR` for your host.

```bash
STEWARD_DIR=/opt/steward
cd "$STEWARD_DIR"
bun install --frozen-lockfile
```

Create `$STEWARD_DIR/.env` from [`../.env.example`](../.env.example). At minimum, a production
server needs independently generated values for:

- `DATABASE_URL`
- `STEWARD_MASTER_PASSWORD`
- `STEWARD_KDF_SALT`
- `STEWARD_JWT_SECRET`
- `STEWARD_EMAIL_CODE_SECRET`
- `STEWARD_AUDIT_HMAC_KEY`
- `STEWARD_EXECUTION_AUTH_SECRET`
- `STEWARD_PROXY_REQUEST_SIGNING_SECRETS`
- `POSTGRES_PASSWORD` when the local Compose database is used

Generate each secret independently. `STEWARD_JWT_SECRET` is canonical and must contain at least 32
characters in production; `STEWARD_SESSION_SECRET` is only a deprecated migration alias. Never
reuse the vault master password as JWT material.

Set `STEWARD_BIND_HOST=127.0.0.1` when both services are reached through a local reverse proxy. Use
`0.0.0.0` only when a container/private-network topology requires it and network policy prevents
direct public access.

Threat note: credentials, tenant keys, and administrative requests must never cross a public or
shared network over cleartext HTTP. Terminate TLS before either service, or keep service-to-service
HTTP on an isolated host or container network that is not reachable by untrusted workloads.

## Service units

Run the services as the dedicated `steward` user. Install the hardened units shipped in the
repository rather than copying an abbreviated unit from documentation. Review their paths and
permissions first; they assume the checkout is `/opt/steward` and the environment file is readable
only by the service account.

```bash
sudo cp deploy/steward.service /etc/systemd/system/steward.service
sudo cp deploy/steward-proxy.service /etc/systemd/system/steward-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now steward steward-proxy
```

## Update

Update the checked-out source through the repository's normal release process, reinstall locked
dependencies, apply pending migrations, and restart both services. Preserve the previous release
artifact or commit so rollback does not depend on downloading new material during an incident.

```bash
cd /opt/steward
bun install --frozen-lockfile
bun run packages/db/src/migrate.ts
sudo systemctl restart steward steward-proxy
```

Run migration commands against a tested backup first. Follow
[`../docs/runbooks/backup-restore.md`](../docs/runbooks/backup-restore.md) and
[`../docs/runbooks/key-rotation.md`](../docs/runbooks/key-rotation.md) for data recovery and secret
rotation.

## Verify

Health responses report the version built into the running service; do not compare them with a
version copied into this guide.

```bash
curl --fail http://127.0.0.1:3200/health
curl --fail http://127.0.0.1:3200/ready
curl --fail http://127.0.0.1:8080/health
sudo systemctl --no-pager --full status steward steward-proxy
```

`/health` proves that the process can answer HTTP. `/ready` is the stronger API dependency check.
A deployment is not validated until authentication, a permitted operation, a denied operation,
audit persistence, and proxy request signing have also been exercised against that exact release.

## Troubleshooting

```bash
sudo journalctl -u steward -u steward-proxy --since "10 minutes ago" --no-pager
```

Common startup failures are missing required secrets, an unreachable database or Redis service,
unapplied migrations, invalid production custody configuration, and occupied listen ports. Keep
credentials and full connection strings out of tickets and logs.
