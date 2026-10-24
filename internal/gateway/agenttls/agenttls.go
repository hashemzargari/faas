// Package agenttls builds the HTTP clients the gateway uses for data-plane
// (shard) and control-plane traffic.
//
// The important property is fail-closed with an explicit, visible transition:
//
//	require  TLS only; a plaintext peer is a hard error (production default)
//	auto     TLS first, fall back to plaintext per endpoint during a mixed-mode
//	         rollout only; every downgrade is logged
//	off      plaintext; only reachable through --insecure/dev and surfaced in
//	         /healthz
//
// TLS 1.3 only (pki.MinTLSVersion); client certificates are presented when
// configured, and --require-mtls makes them mandatory.
package agenttls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

// Mode is the data-plane transport security mode.
type Mode string

const (
	// ModeOff is plaintext (insecure; explicit dev/transitional only).
	ModeOff Mode = "off"
	// ModeAuto tries TLS and falls back to plaintext per endpoint (mixed-mode
	// rollout), logging every downgrade.
	ModeAuto Mode = "auto"
	// ModeRequire is TLS only.
	ModeRequire Mode = "require"
)

// ParseMode validates a --agent-tls value.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeOff, "":
		return ModeOff, nil
	case ModeAuto:
		return ModeAuto, nil
	case ModeRequire:
		return ModeRequire, nil
	}
	return "", fmt.Errorf("agenttls: invalid mode %q (want off|auto|require)", s)
}

// Options configures the client builder.
type Options struct {
	Mode Mode
	// CAFile verifies peers. Required unless Mode is off.
	CAFile string
	// CertFile/KeyFile present the gateway's client certificate (mTLS). Optional
	// for the server-auth-only migration phase, required when RequireMTLS.
	CertFile string
	KeyFile  string
	// RequireMTLS rejects peers that do not authenticate us with a client
	// certificate and forbids the auto fallback.
	RequireMTLS bool
	// DialTimeout bounds connection establishment. Defaults to 5 s.
	DialTimeout time.Duration
	// Logger receives downgrade warnings; defaults to slog.Default().
	Logger *slog.Logger
}

// Info is the security posture, exposed through /healthz and logs. It contains
// no key material.
type Info struct {
	Mode        Mode `json:"mode"`
	Insecure    bool `json:"insecure"`
	RequireMTLS bool `json:"require_mtls"`
	// NotAfter is the client certificate expiry (zero when no client cert).
	NotAfter    time.Time `json:"not_after,omitempty"`
	Fingerprint string    `json:"cert_fingerprint,omitempty"`
}

// NewClient builds an *http.Client for agent endpoints.
//
// The returned client always speaks HTTPS in require/auto modes; the per-dial
// TLS configuration is filled with the peer's host name (Go requires a non-empty
// ServerName for hostname verification, so this must never be left empty).
func NewClient(opts Options) (*http.Client, Info, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	info := Info{Mode: opts.Mode, Insecure: opts.Mode == ModeOff, RequireMTLS: opts.RequireMTLS}

	base := &tls.Config{MinVersion: pki.MinTLSVersion}
	if opts.Mode != ModeOff {
		if opts.CAFile == "" {
			return nil, info, fmt.Errorf("%w: data-plane TLS requires --ca-cert", pki.ErrMissingCA)
		}
		// pki.ClientConfig insists on a ServerName; the transport overrides it per
		// dial with the actual peer host, so this placeholder never verifies
		// anything. It exists only to reuse the one validated constructor.
		cfg, err := pki.ClientConfig(opts.CAFile, opts.CertFile, opts.KeyFile, "peer.invalid")
		if err != nil {
			return nil, info, err
		}
		base = cfg
		if len(cfg.Certificates) > 0 {
			leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
			if err != nil {
				return nil, info, fmt.Errorf("agenttls: parse client certificate: %w", err)
			}
			info.NotAfter = leaf.NotAfter
			info.Fingerprint = pki.Fingerprint(leaf)
		} else if opts.RequireMTLS {
			return nil, info, fmt.Errorf("%w: --require-mtls needs --tls-cert and --tls-key for the gateway identity", pki.ErrMissingCert)
		}
	}

	t := &transport{
		mode:        opts.Mode,
		base:        base,
		requireMTLS: opts.RequireMTLS,
		dialer:      &net.Dialer{Timeout: opts.DialTimeout, KeepAlive: 30 * time.Second},
		log:         opts.Logger,
		plaintext:   make(map[string]bool),
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           t.dialer.DialContext,
		DialTLSContext:        t.dialTLS,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.DialTimeout,
		ResponseHeaderTimeout: 0,
		// Shard traffic is HTTP/1.1; the plaintext fallback path cannot negotiate
		// h2 anyway and mixing h2 expectations complicates a mixed-mode rollout.
		ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: tr}, info, nil
}

// Scheme returns the URL scheme agent endpoints must be addressed with.
func (i Info) Scheme() string {
	if i.Mode == ModeOff {
		return "http"
	}
	return "https"
}

type transport struct {
	mode        Mode
	base        *tls.Config
	requireMTLS bool
	dialer      *net.Dialer
	log         *slog.Logger

	mu        sync.Mutex
	plaintext map[string]bool
}

func (t *transport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, t.configFor(addr))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if t.mode == ModeAuto && !t.requireMTLS && isPlaintextPeer(err) {
			// Mixed-mode rollout: the endpoint is still a plaintext agent. The
			// plaintext server usually closes the connection after choking on our
			// ClientHello, so dial a fresh one before returning it.
			_ = tlsConn.Close()
			plain, derr := t.dialer.DialContext(ctx, network, addr)
			if derr != nil {
				return nil, derr
			}
			t.notePlaintext(addr)
			return plain, nil
		}
		_ = conn.Close()
		return nil, pki.ExplainTLSHandshakeError(err, addr)
	}
	return tlsConn, nil
}

func (t *transport) configFor(addr string) *tls.Config {
	cfg := t.base.Clone()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	// Never empty: an empty ServerName disables hostname verification.
	cfg.ServerName = host
	return cfg
}

func (t *transport) notePlaintext(addr string) {
	t.mu.Lock()
	already := t.plaintext[addr]
	t.plaintext[addr] = true
	t.mu.Unlock()
	if !already {
		t.log.Warn("data-plane peer is still plaintext; continuing because --agent-tls=auto (mixed-mode rollout). Switch to --require-mtls once every agent has TLS.",
			"peer", addr)
	}
}

// plaintextPeers returns a sorted snapshot for diagnostics.
func (t *transport) plaintextPeers() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.plaintext))
	for addr := range t.plaintext {
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

func isPlaintextPeer(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"first record does not look like a TLS handshake",
		"server gave HTTP response to HTTPS client",
		"tls: oversized record",
		// An HTTP server that does not understand TLS typically closes after
		// reading the ClientHello, which surfaces as EOF/reset on our side.
		"EOF",
		"connection reset by peer",
		"broken pipe",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// ErrPlaintextPeer reports that a peer spoke plaintext while strict TLS was
// required. Callers can errors.Is it.
var ErrPlaintextPeer = errors.New("agenttls: peer is plaintext but TLS is required")

// RequireTLSError wraps a plaintext downgrade attempt in strict mode with an
// actionable message.
func RequireTLSError(addr string) error {
	return fmt.Errorf("%w: %s answered in plaintext; enable TLS on that agent or run --agent-tls=auto during the mixed-mode rollout",
		ErrPlaintextPeer, addr)
}
