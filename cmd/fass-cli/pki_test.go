package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fass-storage/fass/internal/pki"
)

func TestPKIInitIssueServerClientInspect(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"pki", "init", "--dir", caDir, "--cn", "test-ca"}, &out, &errOut); code != 0 {
		t.Fatalf("pki init exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "CA created") || !strings.Contains(out.String(), "fingerprint:") {
		t.Fatalf("init output = %q", out.String())
	}
	keyInfo, err := os.Stat(filepath.Join(caDir, pki.CAKeyFile))
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode = %o, want 0600", keyInfo.Mode().Perm())
	}

	// Server certificate with both DNS and IP SANs (the SAN rule).
	serverDir := filepath.Join(root, "coordinator")
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{
		"pki", "issue-server", "--ca-dir", caDir, "--dir", serverDir,
		"--dns", "coordinator.example.internal", "--dns", "fass-coordinator",
		"--ip", "127.0.0.1",
	}, &out, &errOut); code != 0 {
		t.Fatalf("issue-server exit = %d, stderr = %s", code, errOut.String())
	}
	certPEM, err := os.ReadFile(filepath.Join(serverDir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "coordinator.example.internal" {
		t.Fatalf("DNS SANs = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IP SANs = %v", cert.IPAddresses)
	}
	keyInfo, err = os.Stat(filepath.Join(serverDir, "tls.key"))
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("issued key mode = %v (err %v), want 0600", keyInfo, err)
	}

	// Client identity must carry the clientAuth EKU.
	clientDir := filepath.Join(root, "console-client")
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{
		"pki", "issue-client", "--ca-dir", caDir, "--dir", clientDir, "--identity", "console",
	}, &out, &errOut); code != 0 {
		t.Fatalf("issue-client exit = %d, stderr = %s", code, errOut.String())
	}
	clientPEM, err := os.ReadFile(filepath.Join(clientDir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := pki.ParseCertificate(clientPEM)
	if err != nil {
		t.Fatal(err)
	}
	foundClientAuth := false
	for _, usage := range clientCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Fatalf("client cert EKU = %v, want clientAuth", clientCert.ExtKeyUsage)
	}

	// inspect prints the SANs and expiry an operator checks.
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"pki", "inspect", "--cert", filepath.Join(serverDir, "tls.crt")}, &out, &errOut); code != 0 {
		t.Fatalf("inspect exit = %d, stderr = %s", code, errOut.String())
	}
	for _, want := range []string{"DNS SANs:", "coordinator.example.internal", "127.0.0.1", "fingerprint:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("inspect output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPKIErrors(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	outDir := filepath.Join(root, "out")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"pki", "init", "--dir", caDir}, &out, &errOut); code != 0 {
		t.Fatalf("pki init for test: %d %s", code, errOut.String())
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown subcommand", []string{"pki", "frobnicate"}, "unknown pki command"},
		{"init without dir", []string{"pki", "init"}, "--dir is required"},
		{"server without SANs", []string{"pki", "issue-server", "--ca-dir", caDir, "--dir", outDir}, "at least one --dns or --ip"},
		{"server invalid IP", []string{"pki", "issue-server", "--ca-dir", caDir, "--dir", outDir, "--ip", "not-an-ip"}, "invalid --ip"},
		{"client without identity", []string{"pki", "issue-client", "--ca-dir", caDir, "--dir", outDir}, "--identity are required"},
		{"inspect missing cert", []string{"pki", "inspect", "--cert", filepath.Join(root, "nope.crt")}, "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), tc.args, &out, &errOut)
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (usage); stderr = %s", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("stderr = %q, want substring %q", errOut.String(), tc.want)
			}
		})
	}
}

func TestPKIHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"pki", "--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "SAN rule") || !strings.Contains(out.String(), "issue-server") {
		t.Fatalf("help output = %q", out.String())
	}
}
