package main

import (
	"testing"
	"time"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.disk != "./data" || cfg.port != 7100 {
		t.Fatalf("disk/port defaults = %q/%d", cfg.disk, cfg.port)
	}
	if cfg.coordURL != "http://127.0.0.1:7000" {
		t.Fatalf("coordinator default = %q", cfg.coordURL)
	}
	if !cfg.scrub || !cfg.repair {
		t.Fatalf("scrub/repair defaults = %v/%v", cfg.scrub, cfg.repair)
	}
	if cfg.heartbeat != 5*time.Second || cfg.shutdown != 15*time.Second {
		t.Fatalf("interval defaults = %v/%v", cfg.heartbeat, cfg.shutdown)
	}
	if cfg.reservePct != 5 || cfg.maxShard != 32<<20 {
		t.Fatalf("capacity defaults = %v/%d", cfg.reservePct, cfg.maxShard)
	}
	if cfg.scrubPeriod != 168*time.Hour || cfg.scrubRate != 50<<20 {
		t.Fatalf("scrub defaults = %v/%d", cfg.scrubPeriod, cfg.scrubRate)
	}
}

func TestParseFlagsValues(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--disk", "/data",
		"--disk-id", "disk-explicit-1",
		"--port", "7200",
		"--nexus-id", "nexus-a",
		"--node-id", "node-1",
		"--coordinator-url", "coord:7000",
		"--secret", "abc",
		"--reserve-pct", "7.5",
		"--max-shard-bytes", "8388608",
		"--scrub=false",
		"--repair=false",
		"--heartbeat-interval", "2s",
		"--log-level", "debug",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.disk != "/data" || cfg.diskID != "disk-explicit-1" || cfg.port != 7200 || cfg.nexusID != "nexus-a" ||
		cfg.nodeID != "node-1" || cfg.coordURL != "coord:7000" || cfg.secret != "abc" ||
		cfg.reservePct != 7.5 || cfg.maxShard != 8388608 ||
		cfg.scrub || cfg.repair || cfg.heartbeat != 2*time.Second || cfg.logLevel != "debug" {
		t.Fatalf("parsed config = %+v", cfg)
	}
}

func TestParseFlagsErrors(t *testing.T) {
	cases := [][]string{
		{"--port", "-1"},
		{"--port", "70000"},
		{"--reserve-pct", "-1"},
		{"--reserve-pct", "100"},
		{"--max-shard-bytes", "0"},
		{"--heartbeat-interval", "0s"},
		{"unexpected"},
		{"--not-a-flag"},
	}
	for _, args := range cases {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("parseFlags(%v) succeeded, want error", args)
		}
	}
}

func TestParseFlagsVersion(t *testing.T) {
	cfg, err := parseFlags([]string{"--version"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !cfg.showVersion {
		t.Fatal("--version not honoured")
	}
}
