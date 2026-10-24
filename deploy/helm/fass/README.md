# FASS Helm chart

Deploys the FASS control plane (coordinator, gateways, console) and the
per-disk storage agents on Kubernetes. The full operational story — sizing,
TLS/certificate lifecycle, upgrade order, rollback, day-2 checks, known product
gaps — is [docs/09-deployment.md](../../../docs/09-deployment.md); this file is
the chart reference. The CA/certificate runbook is
[docs/08-operations.md §4](../../../docs/08-operations.md).

```bash
# 1. Inspect what a 3-site values file would render (no cluster needed):
helm template fass ./deploy/helm/fass -f ./deploy/helm/fass/values-three-site.yaml

# 2. Create the Secrets the chart references (it never creates or generates any),
#    label the nodes, prepare the host disk directories, then:
helm install fass ./deploy/helm/fass -n fass -f ./deploy/helm/fass/values-three-site.yaml
```

Example values files:

| File | Topology | TLS | Use |
|---|---|---|---|
| `values-dev.yaml` | 3 Nexuses × 2 nodes × 2 disks, ephemeral store, ephemeral key seed | **explicitly off** (`tls.enabled=false` + `allowInsecure=true`) | kind/minikube/evaluation only |
| `values-single-site.yaml` | 1 Nexus × 10 nodes × 2 disks, flat `geo 1+0 / local 16+4` | on (existing Secrets) | one datacenter, no site-loss tolerance |
| `values-three-site.yaml` | 3 Nexuses × 10 nodes × 2 disks, `geo 2+1 / local 16+4` | on (existing Secrets) | recommended production shape |

## TLS is the default and fails closed

Every FASS component (coordinator listener, gateway S3 edge and data/control
clients, agent shard listener and repair clients) **refuses to start without
certificate material** unless a dev-only plaintext switch is explicit. The chart
follows that:

* `tls.enabled: true` in `values.yaml`, `values-single-site.yaml` and
  `values-three-site.yaml`.
* `values-dev.yaml` sets `tls.enabled: false` **and** `allowInsecure: true`; the
  rendered manifests then carry a `WARNING: tls.enabled=false` comment and pass
  `FASS_COORDINATOR_DEV`, `FASS_GATEWAY_DEV`/`FASS_GATEWAY_INSECURE` and
  `FASS_AGENT_INSECURE` explicitly. Plaintext is never a silent default.
* Certificates are **existing Secrets by reference** — never generated, never
  inlined. The chart cannot see whether a referenced Secret exists at render
  time; it does fail when the *reference* is empty (see validation below), and a
  missing Secret surfaces as `CreateContainerConfigError` naming it.

### Required Secret references (TLS on)

| Value | Contents |
|---|---|
| `tls.caSecret` / `tls.caKey` | cluster CA **public certificate** only (the CA key stays offline) |
| `coordinator.tls.certSecret` / `keySecret` | coordinator listener cert + key |
| `gateway.tls.existingSecret` | gateway S3 listener cert + key (unless an LB terminates S3 TLS) |
| `gateway.mtls.existingSecret` | gateway clientAuth identity (required when `tls.requireMTLS=true`) |
| `agents.tls.existingSecret` **or** `agents.nodes[].tlsSecret` | agent shard-listener cert(s) |
| `agents.tls.clientCertSecret` | agent repair clientAuth identity (required when `agents.repair=true`) |
| `console.tls.existingSecret` | console HTTPS listener (when `console.tls.enabled=true`) |
| `console.coordinatorClient.existingSecret` | console clientAuth identity (required when `tls.requireMTLS=true`) |

`gateway.keySeed.existingSecret`, `console.auth.existingSecret`,
`coordinator.db.existingSecret` (PostgreSQL) and the per-disk announce Secrets
are required in both modes — see NOTES.txt after `helm install`.

### SAN rule (the one that stalls rollouts)

**Every name a peer dials must be in the certificate** — DNS names *and* IPs.
The chart runs agents with `hostNetwork: true`, so an agent announces
`status.hostIP:port`; a shared agent certificate therefore needs every node IP
as an IP SAN, and per-node certificates (`agents.nodes[].tlsSecret`) are
recommended. If you switch an agent to pod networking, include the pod DNS name
instead. Coordinator and gateway certificates need the service DNS names peers
use (`<release>-coordinator`, `...svc`, `...svc.cluster.local`), and the gateway
S3 certificate needs the client-facing name.

The exact `fass pki init|issue-server|issue-client` invocations with SAN
examples are in the chart's rendered `NOTES.txt` (written for your release's
service names). There is no `fass-agent pki` subcommand yet: agent certificates
are issued with the same `fass pki` tool (a documented gap, not an
invented command).

Typical SAN coverage:

```
coordinator: --dns <release>-coordinator
             --dns <release>-coordinator.<ns>.svc
             --dns <release>-coordinator.<ns>.svc.cluster.local
gateway S3:  --dns s3.example.com --ip <load-balancer-ip>
agent node:  --ip <node-ip> --dns <node-fqdn>
```

Rotate certificates before the renewal window; agents/gateways reload them
without a restart (docs/09 §Certificate lifecycle).

## Design notes

**One agent per disk, pinned per node.** Each disk is its own container in a
per-node Deployment, with a `hostPath` volume and
`nodeSelector: kubernetes.io/hostname`. The node name is passed as `--node-id`
and the host IP as the announced `--hostname`, so the endpoint the coordinator
hands to gateways is reachable (`hostNetwork: true` by default).

One Deployment is rendered per node rather than one DaemonSet per Nexus because
each disk has a *different one-time announce Secret*; Kubernetes cannot vary a
`secretKeyRef` per pod of a DaemonSet. Each agent container gets its disk's
Secret mounted read-only and uses `FASS_AGENT_SECRET_FILE`, so the announce
credential never appears in argv (a per-node Secret-controller design could
collapse this to one DaemonSet per Nexus later).

**The chart does not schedule the AAG.** Pod anti-affinity cannot express the
coordinator's placement invariant (at most `aag` shards of one shard-set per
Node). The chart's job is to make the invariant *possible*: it pins agents to
their node, refuses more disks per node than `aag` by default, and refuses
declared Nexus topologies that placement cannot fill
(`nodes ≥ ceil((local_n+local_k)/aag)` and at least `local_n+local_k` agents
per Nexus). See docs/09 §"AAG is a per-Node rule".

**Probes and TLS.** Gateway probes hit the plaintext admin listener
(`:9000/healthz`, `/readyz`). Coordinator, agent and (when enabled) console TLS
listeners use exec probes with the image's `/usr/local/bin/fass-dev-healthcheck
-insecure` against `127.0.0.1`: the probe verifies liveness locally and skips
certificate verification (SANs are peer names, not loopback); real peer traffic
is still verified. Do not interpret `-insecure` there as a security setting.

## Validation the chart performs

`helm template` fails with an actionable message when:

* `tls.enabled=true` but `tls.caSecret`, `coordinator.tls.certSecret/keySecret`,
  `gateway.tls.existingSecret`, any agent listener certificate
  (`agents.tls.existingSecret` or per-node `tlsSecret`), (with
  `agents.repair=true`) `agents.tls.clientCertSecret`, (with
  `console.tls.enabled=true`) `console.tls.existingSecret`, or (with
  `tls.requireMTLS=true`) `console.coordinatorClient.existingSecret` is empty —
  the error names the value;
* `tls.enabled=true` with `gateway.coordinatorURL` not `https://`;
* `tls.enabled=false` without `tls.allowInsecure=true` (prevents silent
  production plaintext);
* `coordinator.replicas > 1` while `dbDriver=embedded` (single-writer store;
  switch to `dbDriver=postgres` for control-plane HA), or `dbDriver=postgres`
  without `coordinator.db.existingSecret`;
* the gateway has neither a key-seed Secret nor `devMode=true`;
* `aag` is outside `1..local_n+local_k`;
* a Nexus declares fewer nodes than `ceil((local_n+local_k)/aag)`, or fewer
  agents than `local_n+local_k`;
* a node has more disks than `aag` (override with
  `agents.allowAgentsPerNodeExceedingAAG=true` only after reading docs/09);
* a disk is missing its announce Secret or `hostPath`;
* two disks on a node resolve to the same port.

Escape hatches: `agents.skipTopologyValidation=true` for unusual-but-deliberate
topologies (the coordinator is still authoritative and will refuse infeasible
placements at write time).

## Day-2

```bash
kubectl -n fass get pods -o wide
kubectl -n fass rollout status deploy -l app.kubernetes.io/component=gateway
helm upgrade fass ./deploy/helm/fass -n fass -f values-three-site.yaml

# Certificate expiry (agents/gateways report cert_not_after; cluster status warns
# inside the renewal window) and the repair queue:
fass --coordinator https://coordinator.example:7000 cluster status
curl --cacert ca.crt -fsS https://coordinator.example:7000/v1/repair/status | jq .
```

Upgrade **coordinator → gateways → agents**, one failure domain at a time; see
docs/09-deployment.md §Upgrade. For the strict-mTLS rollout, run every component
with `tls.requireMTLS=false` first, confirm `security.insecure=false` and
`require_mtls=false` on each `/healthz`, then flip the flag in one `helm upgrade`.
Strict mTLS works with the console enabled: create a clientAuth identity
(`fass pki issue-client --identity console`) and point
`console.coordinatorClient.existingSecret` at its Secret. The console can also
serve its own HTTPS listener (`console.tls.enabled`).
`make deploy-lint` runs `helm lint` + `helm template` for every values file and
`systemd-analyze verify` for the systemd units (skipped cleanly when tools are
absent).
