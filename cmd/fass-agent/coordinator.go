package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/agent/coordclient"
	"github.com/fass-storage/fass/internal/pki"
)

// Control-plane TLS is configured independently from the shard-listener TLS:
// an operator may put the coordinator behind a different CA than the agent mesh,
// and the flag names must not be conflated. The rules are fail-closed:
//
//	https://  → --coordinator-ca is mandatory; never falls back to plaintext
//	http://   → only with --insecure; TLS flags are then a configuration error
//
// Client certificates are optional (a server-auth-only coordinator is valid),
// but when one is used it must carry the client-auth EKU, otherwise startup
// fails with an actionable error rather than the first announce failing with an
// opaque handshake error.
func buildCoordinatorClient(cfg config, logger *slog.Logger) (*coordclient.Client, error) {
	scheme, urlHost, err := parseCoordinatorURL(cfg.coordURL)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "https":
		return buildTLSCoordinatorClient(cfg, logger, urlHost)
	case "http":
		return buildPlainCoordinatorClient(cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported coordinator URL scheme %q (want http or https)", scheme)
	}
}

// parseCoordinatorURL splits the configured URL without ever silently changing
// an explicit https:// into plaintext. A legacy "host:port" value is treated as
// http (and therefore fails closed unless --insecure is set).
func parseCoordinatorURL(raw string) (scheme, host string, err error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return "", "", errors.New("coordinator URL is empty; set --coordinator-url")
	}
	if !strings.Contains(cleaned, "://") {
		cleaned = "http://" + cleaned
	}
	u, err := url.Parse(cleaned)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid coordinator URL %q", raw)
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("unsupported coordinator URL scheme %q (want http or https)", u.Scheme)
	}
	return scheme, u.Hostname(), nil
}

func buildTLSCoordinatorClient(cfg config, logger *slog.Logger, urlHost string) (*coordclient.Client, error) {
	if cfg.coordCA == "" {
		return nil, errors.New("refusing to use an https:// coordinator without --coordinator-ca: " +
			"set the CA bundle that verifies the coordinator certificate " +
			"(or use http:// with --insecure for a dev-only plaintext control plane)")
	}
	serverName := cfg.coordServerName
	if serverName == "" {
		serverName = urlHost
	}
	if serverName == "" {
		return nil, errors.New("cannot derive the coordinator server name from the URL; set --coordinator-server-name")
	}

	clientCert, clientKey, err := coordinatorClientIdentity(cfg)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := pki.ClientConfig(cfg.coordCA, clientCert, clientKey, serverName)
	if err != nil {
		return nil, fmt.Errorf("coordinator TLS: %w", err)
	}

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 15 * time.Second,
	}
	cli, err := coordclient.New(cfg.coordURL, coordclient.Options{
		HTTPClient: hc,
		Logger:     logger,
		TLSEnabled: true,
		PeerName:   serverName,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("coordinator control-plane TLS enabled",
		"url", cfg.coordURL,
		"server_name", serverName,
		"client_cert", clientCert != "",
	)
	return cli, nil
}

func buildPlainCoordinatorClient(cfg config, logger *slog.Logger) (*coordclient.Client, error) {
	if !cfg.insecure {
		return nil, errors.New("refusing to talk to the coordinator over plaintext http://: " +
			"use an https:// coordinator URL with --coordinator-ca, " +
			"or pass --insecure for a dev-only plaintext control plane")
	}
	if cfg.coordCA != "" || cfg.coordServerName != "" || cfg.coordClientCert != "" || cfg.coordClientKey != "" {
		return nil, errors.New("--insecure conflicts with coordinator TLS flags " +
			"(--coordinator-ca/--coordinator-server-name/--coordinator-client-cert/--coordinator-client-key); " +
			"choose encrypted or plaintext control-plane transport")
	}
	return coordclient.New(cfg.coordURL, coordclient.Options{Logger: logger})
}

// coordinatorClientIdentity resolves the client certificate for the
// coordinator, in order: --coordinator-client-cert/key, then the repair identity
// (--tls-client-cert/key), then the shard-listener identity (--tls-cert/key).
//
// Explicit identities must allow client authentication: a wrong-EKU certificate
// is a configuration error. The shard-listener fallback is best-effort — a
// server-only listener certificate simply means "no client certificate"
// (a server-auth-only coordinator is a valid deployment), and a coordinator
// upgraded to --require-mtls then rejects the announce with an actionable
// coordclient error naming the flags to set.
func coordinatorClientIdentity(cfg config) (certFile, keyFile string, err error) {
	certFile, keyFile = cfg.coordClientCert, cfg.coordClientKey
	source := "--coordinator-client-cert/--coordinator-client-key"
	explicit := true
	if (certFile == "") != (keyFile == "") {
		return "", "", errors.New("--coordinator-client-cert and --coordinator-client-key must be set together")
	}
	if certFile == "" {
		certFile, keyFile = cfg.tlsClientCert, cfg.tlsClientKey
		source = "--tls-client-cert/--tls-client-key (repair identity)"
		if (certFile == "") != (keyFile == "") {
			return "", "", errors.New("--tls-client-cert and --tls-client-key must be set together")
		}
	}
	if certFile == "" {
		certFile, keyFile = cfg.tlsCert, cfg.tlsKey
		source = "--tls-cert/--tls-key (shard-listener identity)"
		explicit = false
	}
	if certFile == "" {
		// Server-auth-only coordinator: no client certificate.
		return "", "", nil
	}
	if err := requireClientAuthUsage(certFile); err != nil {
		if !explicit {
			// A server-only listener certificate is normal; just do not present it
			// as a client identity.
			return "", "", nil
		}
		return "", "", fmt.Errorf("coordinator client identity from %s: %w; "+
			"pass --coordinator-client-cert/--coordinator-client-key with a certificate that "+
			"carries the client-auth EKU", source, err)
	}
	return certFile, keyFile, nil
}
