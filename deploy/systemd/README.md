# FASS on systemd (VM / bare-metal installs)

One **agent per disk**, one gateway (or more) per site, one coordinator for the
cluster. The complete operational story (sizing, upgrade order, rollback, day-2
checks, known gaps) is [docs/09-deployment.md](../../../docs/09-deployment.md).

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
sudo install -d -o fass -g fass -m 0750 /var/lib/fass            # coordinator store, on a data disk
sudo install -d -o fass -g fass -m 0750 /etc/fass                # environment files
sudo install -d -o root -g fass -m 0750 /etc/fass/tls            # gateway certificates
```

## 2. Install the units

```bash
sudo install -m 0644 deploy/systemd/fass-coordinator.service \
                       deploy/systemd/fass-gateway.service \
                       deploy/systemd/fass-console.service \
                       deploy/systemd/fass-agent@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Environment files (`EnvironmentFile=` paths must exist before `start`):

```bash
sudo install -m 0640 -o root -g fass deploy/systemd/examples/coordinator.env.example /etc/fass/coordinator.env
sudo install -m 0600 -o root -g fass deploy/systemd/examples/gateway.env.example     /etc/fass/gateway.env
sudo install -m 0600 -o root -g fass deploy/systemd/examples/console.env.example     /etc/fass/console.env
# edit every CHANGEME value before starting anything
```

## 3. Start in order: coordinator → gateway → console

```bash
sudo systemctl enable --now fass-coordinator
sudo systemctl enable --now fass-gateway
sudo systemctl enable --now fass-console
systemctl status fass-coordinator fass-gateway fass-console
```

If you use PostgreSQL instead of the embedded store, set
`FASS_COORDINATOR_DB_DRIVER=postgres` + `FASS_COORDINATOR_DB_DSN` in
`/etc/fass/coordinator.env` and apply migrations once before the first start
(and before every upgrade):

```bash
sudo -u fass sh -c 'set -a; . /etc/fass/coordinator.env; set +a; exec /usr/local/bin/fass-coordinator migrate'
```

Then create the cluster metadata (RC, Ring, tenants, buckets, access keys)
through the coordinator API; `fass cluster status` should show the coordinator
with zero agents until the storage nodes join.

## 4. One agent per disk

Each disk gets its own unit instance, its own environment file, its own port and
its own directory:

```bash
# node-a1 has two disks mounted at /var/lib/fass/disks/disk0 and .../disk1
sudo install -d -o fass -g fass -m 0750 /var/lib/fass/disks/disk0 /var/lib/fass/disks/disk1

# one environment file per disk (copy the example, edit values)
sudo cp deploy/systemd/examples/agent.env.example /etc/fass/agent-disk0.env
sudo cp deploy/systemd/examples/agent.env.example /etc/fass/agent-disk1.env
#   agent-disk0.env: FASS_AGENT_DISK=/var/lib/fass/disks/disk0 FASS_AGENT_PORT=7100
#   agent-disk1.env: FASS_AGENT_DISK=/var/lib/fass/disks/disk1 FASS_AGENT_PORT=7101
sudo chmod 0600 /etc/fass/agent-disk*.env && sudo chown root:fass /etc/fass/agent-disk*.env

sudo systemctl enable --now fass-agent@disk0.service
sudo systemctl enable --now fass-agent@disk1.service
```

Rules the units assume (override with systemd drop-ins if your layout differs):

* disks are mounted at `/var/lib/fass/disks/<instance>` — this is used by
  `RequiresMountsFor=` and `ReadWritePaths=`;
* every instance has a unique port on that node;
* the coordinator has a matching Node id (`FASS_AGENT_NODE_ID`) and the disk was
  pre-registered with `POST /v1/agents/pending`; the returned one-time secret is
  `FASS_AGENT_SECRET`;
* the agent owns its on-disk identity in `<disk>/state.json`; a replacement disk
  or a mismatched identity makes the unit fail closed (visible with
  `journalctl -u fass-agent@disk0`). Do not "fix" it by deleting the state.

## 5. Logs and verification

```bash
journalctl -u fass-coordinator -f
journalctl -u fass-agent@disk0 -f
curl -fsS http://127.0.0.1:7000/healthz
curl -fsS http://127.0.0.1:8080/healthz          # gateway (or https when TLS is on)
curl -fsS http://127.0.0.1:8081/healthz          # console
fass --endpoint https://s3.example:8443 health
fass cluster status
curl -fsS http://127.0.0.1:7000/v1/repair/status
```

The console has no TLS and no RBAC of its own: keep it on loopback (the example
env file does) and front it with a TLS reverse proxy authenticating against your
SSO. See docs/09-deployment.md §"Known product gaps" for the product changes
that would remove the workarounds here (coordinator TLS/Postgres, agent
`--secret-file`, KMIP, console SSO).
