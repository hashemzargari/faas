package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/agent/transport"
	"github.com/fass-storage/fass/internal/pki"
)

// agentSecurity is the resolved TLS configuration for the agent's two TLS
// roles: the shard listener (server auth, optionally mTLS) and the repair
// client that fetches shards from peer agents (client auth).
//
// Configuration philosophy: TLS is the default and missing material is fatal.
// Plaintext is only reachable through an explicit --insecure, which logs a
// warning on every start and is visible in /v1/healthz. There is no silent
// downgrade path.
type agentSecurity struct {
	serverTLS  *transport.ServerTLS // nil when insecure
	insecure   bool
	scheme     string       // URL scheme for agent endpoints: https unless insecure
	httpClient *http.Client // TLS client for agent-to-agent traffic; nil when insecure
}

// buildAgentSecurity validates the TLS flags and builds the listener and repair
// client configuration. Every combination that could mean "we are not sure
// whether this is encrypted" fails closed with an actionable error.
func buildAgentSecurity(cfg config, logger *slog.Logger) (*agentSecurity, error) {
	tlsMaterialSet := cfg.tlsCert != "" || cfg.tlsKey != "" || cfg.tlsCA != "" ||
		cfg.tlsClientCert != "" || cfg.tlsClientKey != "" || cfg.requireMTLS

	if cfg.insecure {
		if tlsMaterialSet {
			return nil, errors.New("conflicting TLS configuration: --insecure cannot be combined with " +
				"--tls-cert/--tls-key/--tls-ca/--tls-client-cert/--tls-client-key/--require-mtls; " +
				"choose encrypted transport or explicit plaintext, not both")
		}
		logger.Warn("TRANSPORT IS PLAINTEXT: --insecure is set, so shard traffic and repair traffic are " +
			"unauthenticated HTTP; /v1/healthz reports {\"tls\":false,\"insecure\":true}. " +
			"Never use this outside a controlled dev environment.")
		return &agentSecurity{insecure: true, scheme: "http"}, nil
	}

	// Secure default: refuse to start rather than silently serving plaintext.
	if cfg.tlsCert == "" || cfg.tlsKey == "" {
		return nil, errors.New("TLS is required for the shard listener: provide --tls-cert and --tls-key " +
			"(or explicitly opt out with --insecure for a dev-only plaintext listener; /v1/healthz will report it)")
	}
	if cfg.requireMTLS && cfg.tlsCA == "" {
		return nil, errors.New("--require-mtls needs --tls-ca to verify client certificates")
	}
	if cfg.repair && cfg.tlsCA == "" {
		return nil, errors.New("agent-to-agent repair needs --tls-ca to verify peer certificates " +
			"(or --insecure for dev); refusing to fall back to plaintext repair traffic")
	}

	serverTLS, err := transport.NewServerTLS(cfg.tlsCert, cfg.tlsKey, cfg.tlsCA, cfg.requireMTLS, logger)
	if err != nil {
		return nil, err
	}

	sec := &agentSecurity{serverTLS: serverTLS, scheme: "https"}
	if cfg.repair {
		clientCert, clientKey := cfg.tlsClientCert, cfg.tlsClientKey
		if (clientCert == "") != (clientKey == "") {
			return nil, errors.New("--tls-client-cert and --tls-client-key must be set together")
		}
		if clientCert == "" {
			// Default to the agent's own identity. It must carry the client-auth
			// EKU (pki.UsageBoth / IssueClient); server-only certificates will be
			// rejected by a peer that requires mTLS, so fail here with a clear fix.
			clientCert, clientKey = cfg.tlsCert, cfg.tlsKey
		}
		if err := requireClientAuthUsage(clientCert); err != nil {
			return nil, fmt.Errorf("repair client certificate %q: %w", clientCert, err)
		}
		factory := newPeerTLSFactory(cfg.tlsCA, clientCert, clientKey)
		sec.httpClient = newTLSHTTPClient(factory.config)
	}

	info := serverTLS.Info()
	logger.Info("shard listener TLS enabled",
		"mutual", info.Mutual,
		"cert_not_after", info.NotAfter.UTC().Format(time.RFC3339),
		"issuer", info.Issuer,
		"subject", info.Subject,
		"repair_tls", cfg.repair,
	)
	return sec, nil
}

// requireClientAuthUsage checks that the certificate may be used as a TLS
// client certificate before we start repairing over mTLS.
func requireClientAuthUsage(certFile string) error {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	cert, err := pki.ParseCertificate(pemBytes)
	if err != nil {
		return err
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return fmt.Errorf("%w: certificate is not valid for client authentication; issue it with "+
		"pki.UsageBoth/pki.UsageClient or pass --tls-client-cert/--tls-client-key", pki.ErrWrongUsage)
}

// peerTLSFactory builds (and caches) a client TLS config per peer host so peer
// certificates are verified against the peer's own name/SAN. Agent endpoints are
// host:port, so the host is the ServerName.
type peerTLSFactory struct {
	caFile   string
	certFile string
	keyFile  string

	mu    sync.Mutex
	cache map[string]*tls.Config
}

func newPeerTLSFactory(caFile, certFile, keyFile string) *peerTLSFactory {
	return &peerTLSFactory{
		caFile:   caFile,
		certFile: certFile,
		keyFile:  keyFile,
		cache:    make(map[string]*tls.Config),
	}
}

func (f *peerTLSFactory) config(host string) (*tls.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cfg, ok := f.cache[host]; ok {
		return cfg, nil
	}
	cfg, err := pki.ClientConfig(f.caFile, f.certFile, f.keyFile, host)
	if err != nil {
		return nil, fmt.Errorf("agent-to-agent TLS for peer %q: %w", host, err)
	}
	f.cache[host] = cfg
	return cfg, nil
}

// newTLSHTTPClient returns an HTTP client that builds the TLS config per peer
// host (so one client can talk to many agents, each verified by its own name).
func newTLSHTTPClient(configForHost func(host string) (*tls.Config, error)) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			cfg, err := configForHost(host)
			if err != nil {
				return nil, err
			}
			td := &tls.Dialer{NetDialer: dialer, Config: cfg}
			return td.DialContext(ctx, network, addr)
		},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}
