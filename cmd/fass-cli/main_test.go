package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestNoCommandIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "no command given") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "fass ") {
		t.Errorf("version output = %q", stdout.String())
	}

	stdout.Reset()
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") || !strings.Contains(stdout.String(), "cluster status") {
		t.Errorf("help output missing usage: %q", stdout.String())
	}
}

func TestCommandHelpDoesNotNeedCredentials(t *testing.T) {
	isolateEnv(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"cp", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("cp --help exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "fass cp") {
		t.Errorf("cp help = %q", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	isolateEnv(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"frobnicate"}, &stdout, &stderr); code != 1 {
		t.Fatalf("unknown command exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
