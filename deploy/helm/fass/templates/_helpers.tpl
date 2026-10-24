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

{{/* Image reference: repository:tag. */}}
{{- define "fass.image" -}}
{{- $img := .Values.image -}}
{{- printf "%s:%s" $img.repository (default .Chart.AppVersion $img.tag) -}}
{{- end -}}

{{/* In-chart coordinator Service URL. TLS is the default; the port is the same. */}}
{{- define "fass.coordinatorServiceURL" -}}
{{- $scheme := ternary "https" "http" .Values.tls.enabled -}}
{{- printf "%s://%s-coordinator:%v" $scheme (include "fass.fullname" .) .Values.coordinator.listenPort -}}
{{- end -}}

{{/* Effective coordinator URL for a component: explicit value, else the in-chart Service. */}}
{{- define "fass.effectiveCoordinatorURL" -}}
{{- if .url -}}
{{- .url -}}
{{- else -}}
{{- include "fass.coordinatorServiceURL" .root -}}
{{- end -}}
{{- end -}}

{{/* Per-disk port: explicit disk.port wins, else basePort + index. */}}
{{- define "fass.agentPort" -}}
{{- if .disk.port -}}
{{- .disk.port -}}
{{- else -}}
{{- add (int .root.Values.agents.basePort) (int .index) -}}
{{- end -}}
{{- end -}}

{{/* ceil(a/b) for integer validation. */}}
{{- define "fass.ceilDiv" -}}
{{- div (add .a .b -1) .b -}}
{{- end -}}

{{/* Validate declared topology and secret references. The chart cannot see the
     scheduler's actual placement, but it can refuse configurations that are
     guaranteed to be infeasible or that make the AAG invariant incoherent. */}}
{{- define "fass.validate" -}}
{{- $rc := .Values.redundancy -}}
{{- $perGroup := add (int $rc.localN) (int $rc.localK) -}}
{{- $aag := int $rc.aag -}}
{{- if lt (int $rc.geoN) 1 -}}
{{- fail "redundancy.geoN must be >= 1" -}}
{{- end -}}
{{- if lt (int $rc.localN) 2 -}}
{{- fail "redundancy.localN must be >= 2" -}}
{{- end -}}
{{- if or (lt $aag 1) (gt $aag $perGroup) -}}
{{- fail (printf "redundancy.aag must be in 1..local_n+local_k (%d)" $perGroup) -}}
{{- end -}}
{{- if .Values.coordinator.enabled -}}
{{- $driver := .Values.coordinator.dbDriver -}}
{{- if and (ne $driver "embedded") (ne $driver "postgres") -}}
{{- fail (printf "coordinator.dbDriver must be \"embedded\" or \"postgres\", got %q" $driver) -}}
{{- end -}}
{{- if eq $driver "postgres" -}}
{{- if not .Values.coordinator.db.existingSecret -}}
{{- fail "coordinator.db.existingSecret is required when coordinator.dbDriver=postgres: create a Secret with the PostgreSQL DSN (key coordinator.db.dsnKey). See docs/09-deployment.md §4.3." -}}
{{- end -}}
{{- else -}}
{{- if gt (int .Values.coordinator.replicas) 1 -}}
{{- fail "coordinator.replicas > 1 requires coordinator.dbDriver=postgres: the embedded store is single-writer. Either keep replicas=1 or point the coordinator at PostgreSQL. See docs/09-deployment.md §6." -}}
{{- end -}}
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
{{- $tls := .Values.tls -}}
{{- if not $tls.enabled -}}
{{- if not $tls.allowInsecure -}}
{{- fail "tls.enabled=false is a dev-only plaintext opt-out: set tls.allowInsecure=true to acknowledge that all FASS traffic will be unencrypted. Production must keep tls.enabled=true (see docs/09-deployment.md §TLS)." -}}
{{- end -}}
{{- else -}}
{{- if not $tls.caSecret -}}
{{- fail "tls.caSecret is required when tls.enabled=true: create a Secret containing the cluster CA certificate (public cert only, key tls.caKey). See docs/09-deployment.md §TLS." -}}
{{- end -}}
{{- if .Values.coordinator.enabled -}}
{{- if not .Values.coordinator.tls.certSecret -}}
{{- fail "coordinator.tls.certSecret is required when tls.enabled=true: an existing Secret with the coordinator listener certificate (PEM). Generate it with `fass-gateway pki issue-server` and include every name peers dial (service DNS names) as SANs." -}}
{{- end -}}
{{- if not .Values.coordinator.tls.keySecret -}}
{{- fail "coordinator.tls.keySecret is required when tls.enabled=true: an existing Secret with the coordinator listener private key (PEM)." -}}
{{- end -}}
{{- end -}}
{{- if .Values.console.enabled -}}
{{- if and .Values.console.tls.enabled (not .Values.console.tls.existingSecret) -}}
{{- fail "console.tls.existingSecret is required when console.tls.enabled=true: an existing Secret with the console listener certificate/key (tls.crt/tls.key)." -}}
{{- end -}}
{{- if and $tls.requireMTLS (not .Values.console.coordinatorClient.existingSecret) -}}
{{- fail "console.coordinatorClient.existingSecret is required when tls.requireMTLS=true: the coordinator requires a client certificate from the console. Issue one with `fass pki issue-client` and reference its Secret (cert+key)." -}}
{{- end -}}
{{- end -}}
{{- if .Values.gateway.enabled -}}
{{- if and .Values.gateway.tls.enabled (not .Values.gateway.tls.existingSecret) -}}
{{- fail "gateway.tls.existingSecret is required when gateway.tls.enabled=true: an existing Secret with the S3 listener certificate/key." -}}
{{- end -}}
{{- if and $tls.requireMTLS (not .Values.gateway.mtls.existingSecret) -}}
{{- fail "gateway.mtls.existingSecret is required when tls.requireMTLS=true: an existing Secret with a clientAuth certificate for agent/coordinator mTLS (`fass-gateway pki issue-client`)." -}}
{{- end -}}
{{- if .Values.gateway.coordinatorURL -}}
{{- if not (hasPrefix "https://" .Values.gateway.coordinatorURL) -}}
{{- fail "gateway.coordinatorURL must be https:// when tls.enabled=true (plaintext control plane requires tls.enabled=false + allowInsecure)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.agents.enabled -}}
{{- if and .Values.agents.repair .Values.tls.enabled (not .Values.agents.tls.clientCertSecret) -}}
{{- fail "agents.tls.clientCertSecret is required when tls.enabled=true and agents.repair=true: agent-to-agent repair needs a clientAuth certificate (`fass-gateway pki issue-client`). Set agents.repair=false or provide the Secret." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.agents.enabled -}}
{{- $a := .Values.agents -}}
{{- $nodeNames := dict -}}
{{- $nodesPerNexus := dict -}}
{{- $agentsPerNexus := dict -}}
{{- if not $a.nodes -}}
{{- fail "agents.nodes is empty: list at least one node per Nexus (see docs/09-deployment.md §Sizing)" -}}
{{- end -}}
{{- range $node := $a.nodes -}}
{{- if not $node.name -}}
{{- fail "agents.nodes[].name is required (must equal the Kubernetes node name, it becomes --node-id)" -}}
{{- end -}}
{{- if hasKey $nodeNames $node.name -}}
{{- fail (printf "agents.nodes: duplicate node name %q" $node.name) -}}
{{- end -}}
{{- $_ := set $nodeNames $node.name true -}}
{{- if not $node.nexus -}}
{{- fail (printf "agents.nodes[%s].nexus is required" $node.name) -}}
{{- end -}}
{{- if not $node.disks -}}
{{- fail (printf "agents.nodes[%s].disks must list at least one disk (one agent per disk)" $node.name) -}}
{{- end -}}
{{- if and $.Values.tls.enabled (not $.Values.agents.tls.existingSecret) (not $node.tlsSecret) -}}
{{- fail (printf "agents.nodes[%s] needs a shard-listener certificate: set agents.tls.existingSecret (one shared cert whose SANs cover every dialed name, including each node's announced IP) or agents.nodes[%s].tlsSecret (per-node cert; recommended with hostNetwork=true)." $node.name $node.name) -}}
{{- end -}}
{{- if and (gt (len $node.disks) $aag) (not $a.allowAgentsPerNodeExceedingAAG) -}}
{{- fail (printf "agents.nodes[%s] has %d disks but redundancy.aag=%d. AAG is the coordinator's per-Node cap for a shard set; the chart refuses this by default because capacity sizing then depends on a rule most operators miss. Raise redundancy.aag (<= local_n+local_k) or set agents.allowAgentsPerNodeExceedingAAG=true after reading docs/09-deployment.md 'AAG is a per-Node rule'." $node.name (len $node.disks) $aag) -}}
{{- end -}}
{{- $_ := set $nodesPerNexus $node.nexus (add (int (default 0 (get $nodesPerNexus $node.nexus))) 1) -}}
{{- $_ := set $agentsPerNexus $node.nexus (add (int (default 0 (get $agentsPerNexus $node.nexus))) (len $node.disks)) -}}
{{- $ports := dict -}}
{{- range $i, $disk := $node.disks -}}
{{- if not $disk.name -}}
{{- fail (printf "agents.nodes[%s].disks[].name is required" $node.name) -}}
{{- end -}}
{{- if not $disk.hostPath -}}
{{- fail (printf "agents.nodes[%s].disks[%s].hostPath is required (the local disk mount path)" $node.name $disk.name) -}}
{{- end -}}
{{- if not $disk.existingSecret -}}
{{- fail (printf "agents.nodes[%s].disks[%s].existingSecret is required: create a pending agent registration (POST /v1/agents/pending) and store its one-time announce secret in a Secret." $node.name $disk.name) -}}
{{- end -}}
{{- $port := include "fass.agentPort" (dict "root" $ "disk" $disk "index" $i) -}}
{{- if hasKey $ports (toString $port) -}}
{{- fail (printf "agents.nodes[%s]: duplicate agent port %v; one agent per disk needs a unique port per node" $node.name $port) -}}
{{- end -}}
{{- $_ := set $ports (toString $port) true -}}
{{- end -}}
{{- end -}}
{{- if not $a.skipTopologyValidation -}}
{{- $minNodes := include "fass.ceilDiv" (dict "a" $perGroup "b" $aag) | int -}}
{{- range $nexus, $nodes := $nodesPerNexus -}}
{{- if lt (int $nodes) $minNodes -}}
{{- fail (printf "Nexus %q declares %d node(s), but aag=%d caps a shard-set at aag shards per Node and local_n+local_k=%d needs at least %d nodes in the Nexus." $nexus (int $nodes) $aag $perGroup $minNodes) -}}
{{- end -}}
{{- $agents := int (get $agentsPerNexus $nexus) -}}
{{- if lt $agents $perGroup -}}
{{- fail (printf "Nexus %q declares %d agent(s), but local_n+local_k=%d shards of every chunk must land on distinct agents in each Nexus." $nexus $agents $perGroup) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
