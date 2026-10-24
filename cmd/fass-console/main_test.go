package main

import "testing"

// isolateEnv clears the console's environment so tests do not depend on the
// developer's shell.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"FASS_CONSOLE_LISTEN", "FASS_COORDINATOR_URL", "FASS_CONSOLE_USER",
		"FASS_CONSOLE_PASSWORD", "FASS_CONSOLE_READ_ONLY", "FASS_LOG_LEVEL",
		"FASS_LOG_FORMAT",
	} {
		t.Setenv(k, "")
	}
}

func TestParseConfigDefaults(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
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
	if _, err := parseConfig([]string{"--coordinator", "coordinator:7000"}); err == nil {
		t.Fatal("expected a scheme validation error")
	}
}

func TestParseConfigRejectsStrayArgs(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_CONSOLE_PASSWORD", "pw")
	if _, err := parseConfig([]string{"unexpected"}); err == nil {
		t.Fatal("expected an error for positional arguments")
	}
}
