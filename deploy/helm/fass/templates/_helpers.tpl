{{/* Chart name, release-scoped names and labels. */}}

{{- define "fass.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fass.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "fass.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "fass.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fass.labels" -}}
helm.sh/chart: {{ include "fass.chart" . }}
app.kubernetes.io/name: {{ include "fass.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fass
{{- end -}}

{{/* Selector labels for one component. Usage: include "fass.selectorLabels" (dict "root" . "component" "gateway") */}}
{{- define "fass.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fass.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image reference: repository:tag, never "latest" by default. */}}
{{- define "fass.image" -}}
{{- $img := .Values.image -}}
{{- printf "%s:%s" $img.repository (default .Chart.AppVersion $img.tag) -}}
{{- end -}}

{{- define "fass.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end -}}

{{/* The coordinator URL workloads should dial. Empty means "the in-chart Service". */}}
{{- define "fass.coordinatorURL" -}}
{{- if .Values.agents.coordinatorURL -}}
{{- .Values.agents.coordinatorURL -}}
{{- else -}}
{{- printf "http://%s-coordinator:%v" (include "fass.fullname" .) .Values.coordinator.listenPort -}}
{{- end -}}
{{- end -}}

{{- define "fass.agentPort" -}}
{{- /* Per-disk port: explicit disk.port wins, else basePort + index. */ -}}
{{- $root := .root -}}
{{- $index := .index -}}
{{- if .disk.port -}}
{{- .disk.port -}}
{{- else -}}
{{- add (int $root.Values.agents.basePort) (int $index) -}}
{{- end -}}
{{- end -}}

{{/* ceil division helper used by the sizing validations. */}}
{{- define "fass.ceilDiv" -}}
{{- div (add .a .b -1) .b -}}
{{- end -}}

{{/* Validate the topology the operator declared. The chart cannot see the
     scheduler's actual placement, but it can refuse configurations that are
     guaranteed to be infeasible or that silently break the AAG invariant. */}}
{{- define "fass.validate" -}}
{{- $rc := .Values.redundancy -}}
{{- $perGroup := add (int $rc.localN) (int $rc.localK) -}}
{{- if lt (int $rc.geoN) 1 -}}
{{- fail "redundancy.geoN must be >= 1" -}}
{{- end -}}
{{- if lt (int $rc.localN) 2 -}}
{{- fail "redundancy.localN must be >= 2" -}}
{{- end -}}
{{- if or (lt (int $rc.aag) 1) (gt (int $rc.aag) $perGroup) -}}
{{- fail (printf "redundancy.aag must be in 1..local_n+local_k (%d)" $perGroup) -}}
{{- end -}}
{{- if .Values.coordinator.enabled -}}
{{- if gt (int .Values.coordinator.replicas) 1 -}}
{{- fail "coordinator.replicas > 1 is not supported: the coordinator's storage backend is an embedded single-writer store (SQLite); there is no PostgreSQL backend yet. Keep coordinator.replicas=1 and restore from the PVC/backup on failure. See docs/09-deployment.md 'Known product gaps'." -}}
{{- end -}}
{{- if .Values.coordinator.postgres.enabled -}}
{{- fail "coordinator.postgres is not implemented by this FASS release: the coordinator has no DSN flag or PostgreSQL backend. Leave coordinator.postgres.enabled=false (see docs/09-deployment.md 'Known product gaps')." -}}
{{- end -}}
{{- end -}}
{{- if .Values.gateway.enabled -}}
{{- if and (not .Values.gateway.devMode) (not .Values.gateway.keySeed.existingSecret) -}}
{{- fail "gateway.keySeed.existingSecret is required (or set gateway.devMode=true for a throwaway dev cluster). The gateway must be given the tenant key seed; losing it makes existing objects unreadable. See docs/09-deployment.md." -}}
{{- end -}}
{{- if and .Values.gateway.tls.enabled (not .Values.gateway.tls.existingSecret) -}}
{{- fail "gateway.tls.existingSecret is required when gateway.tls.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.console.enabled (not .Values.console.auth.existingSecret) -}}
{{- fail "console.auth.existingSecret is required (keys console-user/console-password); the console refuses to start unauthenticated" -}}
{{- end -}}
{{- if .Values.agents.enabled -}}
{{- $a := .Values.agents -}}
{{- $aag := int $rc.aag -}}
{{- range $nx := $a.nexuses -}}
{{- if not $nx.name -}}
{{- fail "agents.nexuses[].name is required" -}}
{{- end -}}
{{- if not $nx.nodeSelector -}}
{{- fail (printf "agents.nexuses[%s].nodeSelector is required: an unpinned agent DaemonSet can land agents in the wrong Nexus and silently break geo separation. Label the site's nodes and pin with nodeSelector." $nx.name) -}}
{{- end -}}
{{- if not $nx.disks -}}
{{- fail (printf "agents.nexuses[%s].disks must list at least one disk (one agent per disk)" $nx.name) -}}
{{- end -}}
{{- if gt (len $nx.disks) $aag -}}
{{- if not $a.allowAgentsPerNodeExceedingAAG -}}
{{- fail (printf "agents.nexuses[%s] has %d disks per node but redundancy.aag=%d: placement caps shards of one shard-set at aag per Node, so the extra disks would silently go unused (and a migration could mis-size capacity). Raise redundancy.aag (<= local_n+local_k) or set agents.allowAgentsPerNodeExceedingAAG=true after reading docs/09-deployment.md." $nx.name (len $nx.disks) $aag) -}}
{{- end -}}
{{- end -}}
{{- if not $a.skipTopologyValidation -}}
{{- $nodes := int (default 0 $nx.nodes) -}}
{{- if gt $nodes 0 -}}
{{- if lt (mul $nodes (len $nx.disks)) $perGroup -}}
{{- fail (printf "agents.nexuses[%s] declares %d nodes x %d disks = %d agents, but local_n+local_k = %d: placement needs at least that many distinct agents in the Nexus." $nx.name $nodes (len $nx.disks) (mul $nodes (len $nx.disks)) $perGroup) -}}
{{- end -}}
{{- $minNodes := include "fass.ceilDiv" (dict "a" $perGroup "b" $aag) | int -}}
{{- if lt $nodes $minNodes -}}
{{- fail (printf "agents.nexuses[%s] declares %d nodes but aag=%d caps a shard-set at aag shards per Node; local_n+local_k=%d requires at least %s nodes in the Nexus." $nx.name $nodes $aag $perGroup $minNodes) -}}
{{- end -}}
{{- end -}}
{{- range $disk := $nx.disks -}}
{{- if not $disk.name -}}
{{- fail (printf "agents.nexuses[%s].disks[].name is required" $nx.name) -}}
{{- end -}}
{{- if not $disk.existingSecret -}}
{{- fail (printf "agents.nexuses[%s].disks[%s].existingSecret is required: create a pending agent registration (POST /v1/agents/pending) and store its one-time announce secret in a Secret." $nx.name $disk.name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
