package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolateEnv clears every environment variable the CLI reads so tests are
// independent of the developer's shell (and of an actual ~/.fass/config).
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"FASS_ENDPOINT", "FASS_S3_ENDPOINT", "FASS_REGION", "FASS_ACCESS_KEY_ID",
		"FASS_ACCESS_KEY", "FASS_SECRET_ACCESS_KEY", "FASS_SECRET_KEY", "FASS_SECRET",
		"FASS_COORDINATOR_URL", "FASS_COORDINATOR", "FASS_PROFILE", "FASS_CONFIG",
		"FASS_TIMEOUT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION",
		"AWS_DEFAULT_REGION",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("HOME", t.TempDir())
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigFile(t *testing.T) {
	path := writeConfig(t, `
# comment
; another comment
[default]
endpoint = http://127.0.0.1:8080
region = eu-west-1
access_key = dev-access-key
secret_key = "dev-secret-key"

[prod]
endpoint=http://prod:8080
timeout = 90s
`)
	cfg, err := loadConfigFile(path, true)
	if err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if got := cfg["default"]["endpoint"]; got != "http://127.0.0.1:8080" {
		t.Errorf("default endpoint = %q", got)
	}
	if got := cfg["default"]["secret_key"]; got != "dev-secret-key" {
		t.Errorf("quoted value not unquoted: %q", got)
	}
	if got := cfg["prod"]["timeout"]; got != "90s" {
		t.Errorf("prod timeout = %q", got)
	}
}

func TestLoadConfigFileMissing(t *testing.T) {
	// Implicit default config may not exist; that is not an error.
	if _, err := loadConfigFile(filepath.Join(t.TempDir(), "nope"), false); err != nil {
		t.Fatalf("missing implicit config should be fine: %v", err)
	}
	// An explicitly requested config must exist.
	if _, err := loadConfigFile(filepath.Join(t.TempDir(), "nope"), true); err == nil {
		t.Fatal("missing explicit config should fail")
	}
}

func TestLoadConfigFileMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"no equals":  "[default]\nendpoint http://x\n",
		"empty name": "[default]\n = value\n",
	} {
		if _, err := loadConfigFile(writeConfig(t, body), true); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestResolveSettingsPrecedence(t *testing.T) {
	isolateEnv(t)
	path := writeConfig(t, `
[default]
endpoint = http://default:8080
region = eu-west-1
access_key = default-ak
secret_key = default-sk
coordinator = http://default:7000

[prod]
endpoint = http://profile:8080
access_key = profile-ak
secret_key = profile-sk
timeout = 2m
`)
	// Profile values.
	s, err := resolveSettings("prod", path)
	if err != nil {
		t.Fatalf("resolveSettings: %v", err)
	}
	if s.endpoint != "http://profile:8080" || s.accessKey != "profile-ak" || s.timeout != 2*time.Minute {
		t.Fatalf("profile not applied: %+v", s)
	}
	if s.coordinator != defaultCoordinator {
		t.Errorf("coordinator should fall back to the built-in default: %q", s.coordinator)
	}

	// Environment beats the profile.
	t.Setenv("FASS_ENDPOINT", "http://env:8080")
	t.Setenv("FASS_ACCESS_KEY_ID", "env-ak")
	s, err = resolveSettings("prod", path)
	if err != nil {
		t.Fatalf("resolveSettings: %v", err)
	}
	if s.endpoint != "http://env:8080" || s.accessKey != "env-ak" {
		t.Fatalf("env did not override profile: %+v", s)
	}
}

func TestResolveSettingsDefaults(t *testing.T) {
	isolateEnv(t)
	s, err := resolveSettings("", "")
	if err != nil {
		t.Fatalf("resolveSettings: %v", err)
	}
	if s.endpoint != defaultEndpoint || s.region != defaultRegion || s.coordinator != defaultCoordinator {
		t.Fatalf("built-in defaults not applied: %+v", s)
	}
	if s.endpointExplicit {
		t.Error("built-in endpoint must not count as explicit")
	}
	if s.timeout != defaultTimeout {
		t.Errorf("timeout = %v", s.timeout)
	}
}

func TestResolveSettingsUnknownProfile(t *testing.T) {
	isolateEnv(t)
	path := writeConfig(t, "[default]\nendpoint = http://x\n")
	if _, err := resolveSettings("missing", path); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestResolveSettingsBadTimeout(t *testing.T) {
	isolateEnv(t)
	path := writeConfig(t, "[default]\ntimeout = soon\n")
	if _, err := resolveSettings("", path); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestFindCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"plain", []string{"ls"}, 0},
		{"global flag with value", []string{"--profile", "prod", "ls"}, 2},
		{"global flag equals", []string{"--profile=prod", "ls"}, 1},
		{"bool flag", []string{"--json", "ls"}, 1},
		{"only flags", []string{"--json"}, -1},
		{"none", nil, -1},
		{"double dash", []string{"--", "ls"}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findCommand(tc.args)
			if err != nil {
				t.Fatalf("findCommand: %v", err)
			}
			if got != tc.want {
				t.Fatalf("findCommand(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

func TestPrescanConfigFlags(t *testing.T) {
	profile, config, err := prescanConfigFlags([]string{"--profile", "prod"}, []string{"ls", "--config=/tmp/f"})
	if err != nil {
		t.Fatalf("prescan: %v", err)
	}
	if profile != "prod" || config != "/tmp/f" {
		t.Fatalf("prescan = profile %q config %q", profile, config)
	}
}
