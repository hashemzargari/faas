package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/gateway/agenttls"
)

// TestHealthzExposesInsecure is the acceptance requirement that a plaintext
// deployment cannot hide: /healthz must say insecure=true and the mode.
func TestHealthzExposesInsecure(t *testing.T) {
	sec := securityStatus{Insecure: true, AgentMode: string(agenttls.ModeOff), RequireMTLS: false, S3TLS: false}
	rec := httptest.NewRecorder()
	healthHandler("ok", sec)(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Status   string `json:"status"`
		Security struct {
			Insecure  bool   `json:"insecure"`
			AgentMode string `json:"agent_mode"`
			S3TLS     bool   `json:"s3_tls"`
		} `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Security.Insecure || body.Security.AgentMode != "off" {
		t.Fatalf("security block = %+v", body.Security)
	}

	// A TLS deployment reports it explicitly too.
	sec = securityStatus{Insecure: false, AgentMode: "require", RequireMTLS: true, S3TLS: true, CertNotAfter: formatNotAfter(time.Now().Add(time.Hour)), CertFingerprint: "abc123"}
	rec = httptest.NewRecorder()
	healthHandler("ok", sec)(rec, httptest.NewRequest("GET", "/healthz", nil))
	if !strings.Contains(rec.Body.String(), `"insecure":false`) || !strings.Contains(rec.Body.String(), `"require_mtls":true`) {
		t.Fatalf("secure healthz = %s", rec.Body.String())
	}
}

func TestValidateSecurityConfigFailsClosed(t *testing.T) {
	base := config{coordinator: "https://coord:7001", caCert: "/ca.crt", agentTLS: "require"}
	tests := []struct {
		name     string
		mutate   func(*config)
		insecure bool
		mode     agenttls.Mode
		wantErr  string
	}{
		{name: "secure config", mutate: func(c *config) {}, mode: agenttls.ModeRequire},
		{name: "insecure bypass", mutate: func(c *config) { c.caCert = "" }, insecure: true, mode: agenttls.ModeOff},
		{name: "missing CA", mutate: func(c *config) { c.caCert = "" }, mode: agenttls.ModeRequire, wantErr: "requires --ca-cert"},
		{name: "agent tls off without insecure", mutate: func(c *config) {}, mode: agenttls.ModeOff, wantErr: "requires --insecure"},
		{name: "mtls without client cert", mutate: func(c *config) { c.requireMTLS = true }, mode: agenttls.ModeRequire, wantErr: "needs --tls-cert"},
		{name: "http coordinator with TLS enforced", mutate: func(c *config) { c.coordinator = "http://coord:7001" }, mode: agenttls.ModeRequire, wantErr: "must use https"},
		{name: "dev cluster may use a plaintext coordinator", mutate: func(c *config) { c.coordinator = "http://coord:7001"; c.dev = true }, mode: agenttls.ModeRequire},
		{name: "non-dev plaintext coordinator is refused", mutate: func(c *config) { c.coordinator = "http://coord:7001" }, mode: agenttls.ModeRequire, wantErr: "must use https"},
		{name: "unparsable coordinator", mutate: func(c *config) { c.coordinator = "://bad" }, mode: agenttls.ModeRequire, wantErr: "invalid --coordinator"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			err := validateSecurityConfig(cfg, tc.insecure, tc.mode)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
