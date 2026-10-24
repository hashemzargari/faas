package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// isolateEnv clears the console's environment so tests do not depend on the
// developer's shell.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"FASS_CONSOLE_LISTEN", "FASS_COORDINATOR_URL", "FASS_CONSOLE_USER",
		"FASS_CONSOLE_PASSWORD", "FASS_CONSOLE_READ_ONLY", "FASS_LOG_LEVEL",
		"FASS_LOG_FORMAT", "FASS_CONSOLE_TLS_CERT", "FASS_CONSOLE_TLS_KEY",
		"FASS_CONSOLE_TLS_CLIENT_CA", "FASS_CONSOLE_REQUIRE_MTLS",
		"FASS_CONSOLE_COORDINATOR_CA", "FASS_CONSOLE_COORDINATOR_CLIENT_CERT",
		"FASS_CONSOLE_COORDINATOR_CLIENT_KEY", "FASS_CONSOLE_COORDINATOR_SERVER_NAME",
		"FASS_CONSOLE_COORDINATOR_INSECURE",
	} {
		t.Setenv(k, "")
	}
}

func TestParseConfigDefaults(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	cfg, err := parseConfig([]string{"--coordinator-insecure"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if !cfg.coordinatorInsecure {
		t.Error("--coordinator-insecure should be recorded")
	}
	if cfg.listen != "127.0.0.1:8081" {
		t.Errorf("listen = %q", cfg.listen)
	}
	if cfg.coordinator != "http://127.0.0.1:7000" {
		t.Errorf("coordinator = %q", cfg.coordinator)
	}
	if cfg.user != "admin" {
		t.Errorf("user = %q", cfg.user)
	}
	if !cfg.readOnly {
		t.Error("console must default to read-only")
	}
}

func TestParseConfigRequiresPassword(t *testing.T) {
	isolateEnv(t)
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("expected an error when no console password is configured")
	}
}

func TestParseConfigFlagsOverrideEnv(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "env-pw")
	t.Setenv("FASS_CONSOLE_USER", "env-user")
	t.Setenv("FASS_CONSOLE_READ_ONLY", "true")
	cfg, err := parseConfig([]string{
		"--listen", "127.0.0.1:9999",
		"--console-user", "flag-user",
		"--read-only=false",
		"--coordinator-insecure",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.listen != "127.0.0.1:9999" || cfg.user != "flag-user" || cfg.readOnly {
		t.Fatalf("flag overrides not applied: %+v", cfg)
	}
	if cfg.password != "env-pw" {
		t.Errorf("password from env = %q", cfg.password)
	}
}

func TestParseConfigReadOnlyEnv(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	t.Setenv("FASS_CONSOLE_READ_ONLY", "false")
	t.Setenv("FASS_CONSOLE_COORDINATOR_INSECURE", "true")
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.readOnly {
		t.Fatal("FASS_CONSOLE_READ_ONLY=false should enable writes")
	}
}

func TestParseConfigRejectsBadCoordinator(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	if _, err := parseConfig([]string{"--coordinator", "coordinator:7000", "--coordinator-insecure"}); err == nil {
		t.Fatal("expected a scheme validation error")
	}
}

func TestParseConfigPlaintextCoordinatorNeedsExplicitOptIn(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	_, err := parseConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "--coordinator-insecure") {
		t.Fatalf("expected an explicit plaintext opt-in error, got %v", err)
	}
}

func TestParseConfigHTTPSRequiresCA(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	_, err := parseConfig([]string{"--coordinator", "https://coordinator:7000"})
	if err == nil || !strings.Contains(err.Error(), "--coordinator-ca") {
		t.Fatalf("expected a missing-CA error, got %v", err)
	}
}

func TestParseConfigTLSPairs(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"server cert without key", []string{"--coordinator-insecure", "--tls-cert", "c.pem"}, "--tls-cert and --tls-key"},
		{"client cert without key", []string{"--coordinator-insecure", "--coordinator-client-cert", "c.pem"}, "--coordinator-client-cert and --coordinator-client-key"},
		{"require-mtls without listener TLS", []string{"--coordinator-insecure", "--require-mtls", "--tls-client-ca", "ca.pem"}, "--require-mtls needs --tls-cert"},
		{"require-mtls without client CA", []string{"--coordinator-insecure", "--require-mtls", "--tls-cert", "c.pem", "--tls-key", "k.pem"}, "--require-mtls needs --tls-client-ca"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseConfigTLSFromEnv(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	t.Setenv("FASS_CONSOLE_COORDINATOR_CA", "/etc/fass/tls/ca/ca.crt")
	t.Setenv("FASS_CONSOLE_COORDINATOR_CLIENT_CERT", "/etc/fass/tls/client/tls.crt")
	t.Setenv("FASS_CONSOLE_COORDINATOR_CLIENT_KEY", "/etc/fass/tls/client/tls.key")
	cfg, err := parseConfig([]string{"--coordinator", "https://coordinator:7000"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.coordinatorCA != "/etc/fass/tls/ca/ca.crt" ||
		cfg.coordinatorClientCert != "/etc/fass/tls/client/tls.crt" ||
		cfg.coordinatorClientKey != "/etc/fass/tls/client/tls.key" {
		t.Fatalf("TLS env not applied: %+v", cfg)
	}
}

func TestIsTLSVerificationError(t *testing.T) {
	if !isTLSVerificationError(fmt.Errorf("Get \"https://x\": tls: failed to verify certificate: x509: certificate signed by unknown authority")) {
		t.Fatal("expected an x509 string error to be treated as a TLS verification failure")
	}
	if isTLSVerificationError(context.DeadlineExceeded) {
		t.Fatal("a timeout must not be treated as a TLS configuration error")
	}
}

func TestParseConfigRejectsStrayArgs(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	if _, err := parseConfig([]string{"unexpected"}); err == nil {
		t.Fatal("expected an error for positional arguments")
	}
}
