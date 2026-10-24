# FASS on systemd (VM / bare-metal installs)

One **agent per disk**, one gateway (or more) per site, one coordinator for the
cluster. The complete operational story (sizing, TLS/certificate lifecycle,
upgrade order, rollback, day-2 checks, known gaps) is
[docs/09-deployment.md](../../../docs/09-deployment.md); the CA/cert runbook is
[docs/08-operations.md §4](../../../docs/08-operations.md).

TLS is the default and **fails closed**: coordinator, gateway and agents refuse
to start without certificate material. Plaintext exists only behind the
explicit `--dev`/`--insecure` switches on a throwaway host.

## 1. Install the binaries

```bash
git clone <fass> && cd fass && source scripts/env.sh && make build
sudo install -m 0755 bin/fass-coordinator bin/fass-gateway bin/fass-console bin/fass-agent /usr/local/bin/
sudo install -m 0755 bin/fass /usr/local/bin/fass          # operator CLI (make cli)
sudo install -d /usr/local/share/doc/fass
sudo install -m 0644 docs/09-deployment.md /usr/local/share/doc/fass/
```

Create the service user and directories:

```bash
sudo useradd --system --home-dir /var/lib/fass --shell /usr/sbin/nologin fass
sudo install -d -o fass -g fass -m 0750 /var/lib/fass              # coordinator store / agent roots
sudo install -d -o fass -g fass -m 0750 /etc/fass                  # environment files
sudo install -d -o root -g fass -m 0750 /etc/fass/agents           # announce secret files
sudo install -d -o root -g fass -m 0750 \
  /etc/fass/tls/ca /etc/fass/tls/coordinator /etc/fass/tls/gateway \
  /etc/fass/tls/gateway-client /etc/fass/tls/agent /etc/fass/tls/agent-client
```

## 2. Cluster CA and certificates (do this first)

Generate the CA **on an operator workstation**, not on a FASS host: the CA
private key signs every identity in the cluster and must never be needed at
runtime.

```bash
# 1. CA (keep ca.key offline; only ca.crt is distributed)
fass-gateway pki init --dir ./pki/ca --cn fass-cluster-ca

# 2. Coordinator listener — SANs must include every name peers dial
fass-gateway pki issue-server --ca-dir ./pki/ca --dir ./pki/coordinator \
  --dns coordinator.example.internal --ip 10.0.0.10

# 3. Gateway: S3 listener (client-facing name) + clientAuth identity for mTLS
fass-gateway pki issue-server --ca-dir ./pki/ca --dir ./pki/gateway \
  --dns s3.site-a.example --ip 10.0.1.20
fass-gateway pki issue-client --ca-dir ./pki/ca --dir ./pki/gateway-client --identity gateway-1

# 4. Agent on this node — SAN rule: the node FQDN (gateways dial the announced
#    hostname, which defaults to the OS hostname) AND the management IP.
fass-gateway pki issue-server --ca-dir ./pki/ca --dir ./pki/agent \
  --dns node-a1.example.internal --ip 10.0.0.11
fass-gateway pki issue-client --ca-dir ./pki/ca --dir ./pki/agent-client \
  --identity agent-client
```

Install the material with restrictive permissions (certs are public, keys are
not; the CA **key** never leaves the workstation):

```bash
# on every host that runs a component
sudo install -m 0644 ./pki/ca/ca.crt                 /etc/fass/tls/ca/ca.crt
sudo install -m 0644 ./pki/coordinator/tls.crt       /etc/fass/tls/coordinator/tls.crt
sudo install -m 0600 -o root -g fass ./pki/coordinator/tls.key /etc/fass/tls/coordinator/tls.key
```

**SAN checklist** (this is the #1 cause of `x509: certificate is valid for X,
not Y`): every value in a peer's dial target must appear in the certificate —
the coordinator DNS name used in `FASS_COORDINATOR_URL`, the gateway name
clients use for S3, and each agent's announced hostname (OS hostname/FQDN) plus
its management IP. Re-issue with the missing `--dns`/`--ip` if it changes.

## 3. Install the units

```bash
sudo install -m 0644 deploy/systemd/fass-coordinator.service \
                       deploy/systemd/fass-gateway.service \
                       deploy/systemd/fass-console.service \
                       deploy/systemd/fass-agent@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Environment files (`EnvironmentFile=` paths must exist before `start`); the
TLS paths in them match the layout above:

```bash
sudo install -m 0640 -o root -g fass deploy/systemd/examples/coordinator.env.example /etc/fass/coordinator.env
sudo install -m 0600 -o root -g fass deploy/systemd/examples/gateway.env.example     /etc/fass/gateway.env
sudo install -m 0600 -o root -g fass deploy/systemd/examples/console.env.example     /etc/fass/console.env
# edit every CHANGEME value (including hostnames in the cert paths/URLs)
```

The units run with `ProtectSystem=strict` and an explicit read-only
`ReadOnlyPaths=/etc/fass/tls`, so a compromised component cannot rewrite its
own certificate material.

## 4. Start in order: coordinator → gateway → console → agents

```bash
sudo systemctl enable --now fass-coordinator
sudo systemctl enable --now fass-gateway
sudo systemctl enable --now fass-console
systemctl status fass-coordinator fass-gateway fass-console
```

The coordinator must be up (and its certificate trusted) before agents start;
gateways can start before agents and become ready once the coordinator is
reachable. If you use PostgreSQL instead of the embedded store, set
`FASS_COORDINATOR_DB_DRIVER=postgres` + `FASS_COORDINATOR_DB_DSN` in
`/etc/fass/coordinator.env` and apply migrations once before the first start
(and before every upgrade):

```bash
sudo -u fass sh -c 'set -a; . /etc/fass/coordinator.env; set +a; exec /usr/local/bin/fass-coordinator migrate'
```

Then create the cluster metadata (RC, Ring, tenants, buckets, access keys)
through the coordinator API; `fass cluster status` should show the coordinator
with zero agents until the storage nodes join.

## 5. One agent per disk

Each disk gets its own unit instance, environment file, port and directory:

```bash
# node-a1 has two disks mounted at /var/lib/fass/disks/disk0 and .../disk1
sudo install -d -o fass -g fass -m 0750 /var/lib/fass/disks/disk0 /var/lib/fass/disks/disk1

sudo cp deploy/systemd/examples/agent.env.example /etc/fass/agent-disk0.env
sudo cp deploy/systemd/examples/agent.env.example /etc/fass/agent-disk1.env
#   agent-disk0.env: FASS_AGENT_DISK=/var/lib/fass/disks/disk0 FASS_AGENT_PORT=7100
#   agent-disk1.env: FASS_AGENT_DISK=/var/lib/fass/disks/disk1 FASS_AGENT_PORT=7101
#   both: FASS_AGENT_NEXUS_ID/FASS_AGENT_NODE_ID + the per-disk announce secret file
sudo chmod 0600 /etc/fass/agent-disk*.env && sudo chown root:fass /etc/fass/agent-disk*.env

sudo systemctl enable --now fass-agent@disk0.service
sudo systemctl enable --now fass-agent@disk1.service
```

Rules the units assume (override with systemd drop-ins if your layout differs):

* disks are mounted at `/var/lib/fass/disks/<instance>` — used by
  `RequiresMountsFor=` and `ReadWritePaths=`;
* every instance has a unique port on that node;
* the coordinator has a matching Node id (`FASS_AGENT_NODE_ID`) and the disk was
  pre-registered with `POST /v1/agents/pending`; the returned one-time secret is
  written to `FASS_AGENT_SECRET_FILE` (mode 0600) and can be removed after the
  first announce;
* agent certificates belong to `/etc/fass/tls/agent`; the repair client
  identity to `/etc/fass/tls/agent-client` (it must carry the clientAuth EKU);
* the agent owns its on-disk identity in `<disk>/state.json`; a replacement disk
  or a mismatched identity makes the unit fail closed (visible with
  `journalctl -u fass-agent@disk0`). Do not "fix" it by deleting the state.

## 6. Certificate rotation (no restart, no ExecReload)

Certificates are reloaded **in-process** when a listener/peer handshake sees
that the cached certificate is inside its renewal window (one third of the
lifetime, capped at 24 h; a 90-day cert renews 30 days early). Replacing the
files atomically is enough:

```bash
# issue the replacement to the same paths the unit reads, atomically
sudo install -m 0600 -o root -g fass ./pki/agent.new/tls.key /etc/fass/tls/agent/tls.key
sudo install -m 0644 ./pki/agent.new/tls.crt                  /etc/fass/tls/agent/tls.crt
# in-flight connections finish on the old certificate; the next handshake uses the new one
```

There is deliberately **no `ExecReload`**: a reload would only restart the
process, and a restart of an agent starts a repair clock. Use
`systemctl restart` only for flag changes.

Rotate the CA itself by issuing a **new CA** and rolling every certificate
(coordinator → gateways → agents, one failure domain at a time); there is no
cross-signed CA bundle support in this release.

## 7. Logs and verification

```bash
journalctl -u fass-coordinator -f
journalctl -u fass-agent@disk0 -f
curl --cacert /etc/fass/tls/ca/ca.crt -fsS https://127.0.0.1:7000/healthz   # SAN must cover 127.0.0.1 or use the DNS name
curl -fsS http://127.0.0.1:9000/readyz          # gateway admin (plaintext, loopback)
curl -fsS http://127.0.0.1:8081/healthz         # console (plaintext, loopback)
SSL_CERT_FILE=/etc/fass/tls/ca/ca.crt fass --coordinator https://coordinator.example.internal:7000 cluster status
curl --cacert /etc/fass/tls/ca/ca.crt -fsS https://coordinator.example.internal:7000/v1/repair/status
```

Each component's `/healthz` reports a `security` block (`insecure`, `tls`,
`require_mtls`, certificate expiry) — check it after a rollout; `insecure=true`
on a production host is an incident.

The console has no RBAC/OIDC of its own: keep the listener on loopback (the
example env file does) and front it with a TLS reverse proxy, or enable its own
HTTPS listener and client certificate (`FASS_CONSOLE_TLS_*`,
`FASS_CONSOLE_COORDINATOR_CLIENT_*`) when the coordinator runs `--require-mtls`.
See docs/09-deployment.md §"Known product gaps" for the remaining product gaps
(KMIP key custody, console SSO/RBAC, CA-bundle rollover).
