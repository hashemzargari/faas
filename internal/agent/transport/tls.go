package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

// SecurityInfo describes the shard listener's security posture. It is reported
// by /v1/healthz, /v1/stats and the heartbeat so the control plane and an
// operator glancing at a health endpoint can tell whether a deployment is
// actually encrypted.
type SecurityInfo struct {
	Enabled    bool
	Mutual     bool
	Insecure   bool
	NotAfter   time.Time
	RenewalDue bool
	Issuer     string
	Subject    string
}

// ServerTLS owns the shard listener's TLS configuration and its hot-reload
// state.
//
// The certificate is reloaded from disk on a handshake when the currently
// served certificate is inside its renewal window (pki.ShouldRenew) or already
// expired. A reload failure keeps serving the previous certificate — a torn
// file during rotation must never take a healthy listener down — and logs an
// actionable message. The decision of *when* to renew is deliberately delegated
// to internal/pki so the gateway and the agents agree on the renewal window.
type ServerTLS struct {
	certFile string
	keyFile  string
	mutual   bool
	logger   *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	leaf     *x509.Certificate
	lastWarn time.Time
	now      func() time.Time

	config *tls.Config
}

// NewServerTLS loads the listener certificate and returns a TLS config whose
// GetCertificate hot-reloads the certificate before expiry.
//
// requireClient enables mandatory client-certificate verification (mTLS). When
// clientCAFile is set but requireClient is false, peer certificates are
// verified if presented (mixed-mode rollout).
func NewServerTLS(certFile, keyFile, clientCAFile string, requireClient bool, logger *slog.Logger) (*ServerTLS, error) {
	if logger == nil {
		logger = slog.Default()
	}

	base, err := pki.ServerConfig(certFile, keyFile, clientCAFile, requireClient)
	if err != nil {
		return nil, fmt.Errorf("shard listener TLS: %w", err)
	}
	if clientCAFile != "" && !requireClient {
		// Mixed mode: request a client certificate and verify it against the CA
		// when it is presented, but do not require it yet. pki.ServerConfig only
		// loads ClientCAs when requireClient is set, so build the requiring config
		// and relax ClientAuth afterwards.
		cfg, err := pki.ServerConfig(certFile, keyFile, clientCAFile, true)
		if err != nil {
			return nil, fmt.Errorf("shard listener TLS: %w", err)
		}
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		base = cfg
	}
	if len(base.Certificates) == 0 {
		return nil, errors.New("shard listener TLS: pki returned no server certificate")
	}

	cert := base.Certificates[0]
	leaf, err := leafOf(cert)
	if err != nil {
		return nil, fmt.Errorf("shard listener TLS: parse server certificate: %w", err)
	}
	cert.Leaf = leaf

	t := &ServerTLS{
		certFile: certFile,
		keyFile:  keyFile,
		mutual:   requireClient,
		logger:   logger.With("component", "tls"),
		cert:     &cert,
		leaf:     leaf,
		now:      time.Now,
	}
	// crypto/tls only calls GetCertificate when the ClientHello carries SNI or
	// Certificates is empty. Agents are routinely addressed by IP (which cannot
	// carry SNI), so hot reload must not depend on SNI: clear the static list
	// and serve exclusively through GetCertificate. A failed reload still keeps
	// serving the cached certificate, so this does not create a torn-file
	// outage.
	base.Certificates = nil
	base.GetCertificate = t.getCertificate
	t.config = base
	return t, nil
}

// Config is the *tls.Config for the listener. It is never nil.
func (t *ServerTLS) Config() *tls.Config { return t.config }

// Mutual reports whether client certificates are mandatory.
func (t *ServerTLS) Mutual() bool { return t.mutual }

// Info returns the current security posture and certificate expiry.
func (t *ServerTLS) Info() SecurityInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	info := SecurityInfo{Enabled: true, Mutual: t.mutual}
	if t.leaf != nil {
		info.NotAfter = t.leaf.NotAfter
		info.RenewalDue = pki.ShouldRenew(t.leaf)
		info.Issuer = t.leaf.Issuer.CommonName
		info.Subject = t.leaf.Subject.CommonName
	}
	return info
}

// NotAfter reports the expiry of the currently served certificate.
func (t *ServerTLS) NotAfter() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.leaf == nil {
		return time.Time{}, false
	}
	return t.leaf.NotAfter, true
}

// getCertificate implements tls.Config.GetCertificate. It reloads the key pair
// when the served certificate is inside its renewal window or expired, and
// keeps the previous certificate if the files are unreadable (torn rotation).
func (t *ServerTLS) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cert != nil && t.leaf != nil && !pki.ShouldRenew(t.leaf) && !pki.IsExpired(t.leaf) {
		return t.cert, nil
	}

	reloaded, err := tls.LoadX509KeyPair(t.certFile, t.keyFile)
	if err != nil {
		if t.cert != nil {
			t.warnReloadFailed(err)
			return t.cert, nil
		}
		return nil, fmt.Errorf("reload shard TLS certificate: %w", err)
	}
	leaf, err := leafOf(reloaded)
	if err != nil {
		if t.cert != nil {
			t.warnReloadFailed(err)
			return t.cert, nil
		}
		return nil, fmt.Errorf("parse reloaded shard TLS certificate: %w", err)
	}
	reloaded.Leaf = leaf

	rotated := t.leaf == nil ||
		!t.leaf.NotAfter.Equal(leaf.NotAfter) ||
		t.leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0
	t.cert = &reloaded
	t.leaf = leaf

	if rotated {
		attrs := []any{
			"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
			"issuer", leaf.Issuer.CommonName,
			"subject", leaf.Subject.CommonName,
			"mutual", t.mutual,
		}
		if pki.IsExpired(leaf) {
			t.logger.Error("shard TLS certificate is expired; renew/re-enroll it against the cluster CA "+
				"(docs/08-operations.md, TLS rotation)", attrs...)
		} else {
			t.logger.Info("reloaded shard TLS certificate", attrs...)
		}
	}
	return t.cert, nil
}

func (t *ServerTLS) warnReloadFailed(err error) {
	now := t.now()
	if now.Sub(t.lastWarn) < 30*time.Second {
		return
	}
	t.lastWarn = now
	t.logger.Warn("could not reload shard TLS certificate; continuing with the previously loaded certificate",
		"err", err, "cert_file", t.certFile, "key_file", t.keyFile)
}

func leafOf(cert tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// tlsErrorLogWriter routes net/http's TLS handshake errors into slog, annotated
// with pki.ExplainTLSHandshakeError so an operator reads "certificate expired"
// instead of "remote error: tls: bad certificate".
type tlsErrorLogWriter struct {
	logger *slog.Logger
}

func (w tlsErrorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	peer := ""
	if i := strings.Index(msg, " from "); i >= 0 {
		peer = strings.TrimSpace(msg[i+len(" from "):])
	}
	err := pki.ExplainTLSHandshakeError(errors.New(msg), peer)
	attrs := []any{"err", err}
	if peer != "" {
		attrs = append(attrs, "peer", peer)
	}
	w.logger.Warn("shard listener TLS handshake failed", attrs...)
	return len(p), nil
}
