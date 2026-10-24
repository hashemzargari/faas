// Command fass-dev-bootstrap materialises the one-time agent announce secrets
// for the docker-compose dev cluster.
//
// The coordinator's `--dev-bootstrap` mode already created (or reconciled) the
// deterministic dev topology and wrote the payload to
// <data-dir>/dev-bootstrap.json. This helper runs after the coordinator is
// healthy, reads that payload, and writes one secret file per agent:
//
//	/secrets/disk-a1-1.secret   (mode 0600, one trailing newline)
//	...
//
// Agents consume them via --secret-file / FASS_AGENT_SECRET_FILE (task-12), so
// the secret never appears in a compose file, an argv list, or the repository.
//
// It fails closed when a secret is empty: dev-bootstrap mints secrets only for
// agents that are not yet ACTIVE, so an empty secret means the cluster was
// bootstrapped previously. Re-running against an existing data dir would leave
// agents with no way to announce; we tell the operator to reset the volumes
// instead of half-starting the stack.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type payload struct {
	Bucket string  `json:"bucket"`
	RCID   string  `json:"rc_id"`
	Agents []agent `json:"agents"`
}

type agent struct {
	NodeID  string `json:"node_id"`
	NexusID string `json:"nexus_id"`
	DiskID  string `json:"disk_id"`
	Secret  string `json:"secret"`
}

func main() {
	var (
		dataDir  = flag.String("data-dir", "/coord", "directory containing dev-bootstrap.json")
		outDir   = flag.String("out-dir", "/secrets", "directory to write per-agent secret files")
		fileName = flag.String("file", "dev-bootstrap.json", "bootstrap payload file name")
	)
	flag.Parse()

	if err := run(*dataDir, *outDir, *fileName); err != nil {
		fmt.Fprintf(os.Stderr, "fass-dev-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

func run(dataDir, outDir, fileName string) error {
	raw, err := os.ReadFile(filepath.Join(dataDir, fileName))
	if err != nil {
		return fmt.Errorf("read bootstrap payload (is the coordinator running with --dev-bootstrap?): %w", err)
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("parse %s: %w", fileName, err)
	}
	if len(p.Agents) == 0 {
		return fmt.Errorf("bootstrap payload contains no agents")
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	written := 0
	for _, a := range p.Agents {
		if a.DiskID == "" || a.NodeID == "" {
			return fmt.Errorf("bootstrap payload has an agent without node_id/disk_id")
		}
		if strings.ContainsAny(a.DiskID, `/\`) || strings.Contains(a.DiskID, "..") {
			return fmt.Errorf("refusing unsafe disk_id %q", a.DiskID)
		}
		if a.Secret == "" {
			return fmt.Errorf("agent %s/%s has no announce secret: the coordinator reused an existing (ACTIVE) registration. Run `docker compose down -v` for a fresh dev cluster instead of reusing the data volume", a.NodeID, a.DiskID)
		}
		path := filepath.Join(outDir, a.DiskID+".secret")
		// 0600: the secret is a credential, even in dev.
		if err := os.WriteFile(path, []byte(a.Secret+"\n"), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("bootstrap: %s/%s -> %s\n", a.NexusID, a.NodeID, path)
		written++
	}
	fmt.Printf("fass-dev-bootstrap: wrote %d announce secret(s) to %s (bucket=%s rc=%s)\n",
		written, outDir, p.Bucket, p.RCID)
	return nil
}
