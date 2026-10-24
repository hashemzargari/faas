# FASS Helm chart

Deploys the FASS control plane (coordinator, gateways, console) and the
per-disk storage agents on Kubernetes. The full operational story — sizing,
upgrade order, rollback, day-2 checks, known product gaps — is
[docs/09-deployment.md](../../../docs/09-deployment.md); this file is the chart
reference.

```bash
# 1. Inspect what a 3-site values file would render (no cluster needed):
helm template fass ./deploy/helm/fass -f ./deploy/helm/fass/values-three-site.yaml

# 2. Create the Secrets the chart references (it never creates any), label the
#    nodes, prepare the host disk directories, then:
helm install fass ./deploy/helm/fass -n fass -f ./deploy/helm/fass/values-three-site.yaml
```

Example values files:

| File | Topology | Use |
|---|---|---|
| `values-dev.yaml` | 3 Nexuses × 2 nodes × 2 disks, ephemeral store, no TLS, ephemeral key seed | kind/minikube/evaluation |
| `values-single-site.yaml` | 1 Nexus × 10 nodes × 2 disks, flat `geo 1+0 / local 16+4` | one datacenter, no site-loss tolerance |
| `values-three-site.yaml` | 3 Nexuses × 10 nodes × 2 disks, `geo 2+1 / local 16+4`, TLS | recommended production shape |

## Design notes

**One agent per disk, pinned per node.** Each disk is its own container in a
per-node Deployment, with a `hostPath` volume and
`nodeSelector: kubernetes.io/hostname`. The node name is passed as `--node-id`
and the host IP as `--hostname`, so the endpoint announced to the coordinator is
reachable by every gateway (`hostNetwork: true` by default).

One Deployment is rendered per node rather than one DaemonSet per Nexus because
every disk uses a *different one-time announce secret*, and Kubernetes cannot
vary a `secretKeyRef` per pod inside a DaemonSet. This works around a current
product gap: the agent has no `--secret-file`/env configuration yet. Once it
does, the chart can collapse to one DaemonSet per Nexus.

**The chart does not schedule the AAG.** Pod anti-affinity cannot express the
coordinator's placement invariant (at most `aag` shards of one shard-set per
Node). The chart's job is to make the invariant *possible*: it pins agents to
their node, refuses more disks per node than `aag` by default, and refuses
declared Nexus topologies that placement cannot fill
(`nodes ≥ ceil((local_n+local_k)/aag)` and at least `local_n+local_k` agents
per Nexus). See docs/09 §"AAG is a per-Node rule".

**Secrets are references only.** The chart fails rendering when a required
Secret name is missing:
`gateway.keySeed.existingSecret`, `gateway.tls.existingSecret` (when TLS is
on), `console.auth.existingSecret`, `coordinator.db.existingSecret` (when
`dbDriver=postgres`), and per-disk
`agents.nodes[].disks[].existingSecret`. The default `values.yaml` contains
obvious `CHANGEME-*` placeholders so `helm lint` works; never install those.

## Validation the chart performs

`helm template` fails with an actionable message when:

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
```

Upgrade **coordinator → gateways → agents**, one failure domain at a time; see
docs/09-deployment.md §Upgrade. `make deploy-lint` runs `helm lint` +
`helm template` for every values file and `systemd-analyze verify` for the
systemd units (both skipped cleanly when the tools are absent).
