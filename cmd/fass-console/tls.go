package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

// coordinatorURLParts splits a coordinator base URL and never silently changes
// an explicit https:// into plaintext.
func coordinatorURLParts(raw string) (scheme, host string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid coordinator URL %q", raw)
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("unsupported coordinator URL scheme %q (want http or https)", u.Scheme)
	}
	return scheme, u.Hostname(), nil
}

// coordinatorHTTPClient builds the client used for every coordinator request.
// https:// requires a CA bundle (fail closed); a client certificate is
// presented when configured (needed for a coordinator running --require-mtls).
func coordinatorHTTPClient(cfg config) (*http.Client, error) {
	scheme, host, err := coordinatorURLParts(cfg.coordinator)
	if err != nil {
		return nil, err
	}
	if scheme == "http" {
		return &http.Client{Timeout: cfg.httpTimeout}, nil
	}
	serverName := cfg.coordinatorServerName
	if serverName == "" {
		serverName = host
	}
	tlsCfg, err := pki.ClientConfig(cfg.coordinatorCA, cfg.coordinatorClientCert, cfg.coordinatorClientKey, serverName)
	if err != nil {
		return nil, fmt.Errorf("coordinator TLS: %w", err)
	}
	return &http.Client{
		Timeout: cfg.httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}, nil
}

// serverTLSConfig loads the console listener certificate. A nil config means a
// plaintext listener (expected behind a TLS reverse proxy; reported on
// /healthz and in the page banner).
func serverTLSConfig(cfg config) (*tls.Config, error) {
	if cfg.tlsCert == "" && cfg.tlsKey == "" {
		return nil, nil
	}
	return pki.ServerConfig(cfg.tlsCert, cfg.tlsKey, cfg.tlsClientCA, cfg.requireMTLS)
}

// probeCoordinator verifies the coordinator connection at startup. TLS
// verification failures are fatal with an actionable message: an operator must
// see "wrong CA / wrong server name" instead of a console that renders 500s or
// a vague degraded banner. Network failures are not fatal — the console is
// designed to keep serving while the control plane recovers.
func probeCoordinator(ctx context.Context, client *http.Client, baseURL, host string, log *slog.Logger) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("coordinator probe: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if isTLSVerificationError(err) {
			return fmt.Errorf("console: coordinator TLS verification failed for %s: %w\n"+
				"check --coordinator-ca / FASS_CONSOLE_COORDINATOR_CA, --coordinator-server-name, and (for --require-mtls) --coordinator-client-cert/--coordinator-client-key",
				host, pki.ExplainTLSHandshakeError(err, host))
		}
		log.Warn("coordinator not reachable at startup; starting in degraded mode", "coordinator", baseURL, "error", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Warn("coordinator is not healthy at startup; starting in degraded mode", "coordinator", baseURL, "status", resp.StatusCode)
	}
	return nil
}

// isTLSVerificationError reports whether err is a certificate/handshake failure
// (configuration) rather than a connectivity failure (transient).
func isTLSVerificationError(err error) bool {
	var unknownAuth x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &unknownAuth) || errors.As(err, &certInvalid) || errors.As(err, &hostname) || errors.As(err, &verifyErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:")
}
