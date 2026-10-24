// Package pki implements the FASS cluster certificate authority and the TLS
// material helpers shared by the gateway, the agents and the coordinator.
//
// Standard library only: crypto/x509, crypto/ecdsa, crypto/tls. The CA private
// key is needed only to issue certificates; runtime components load their own
// cert/key and the CA *certificate* (never the CA key), so a compromised data
// plane host cannot mint itself a new identity.
//
// Identity model (docs/02 §3, docs/04 §6.2): one internal CA; every component
// presents a client certificate when mTLS is required; peers verify each other
// against the same CA. TLS 1.3 minimum.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Usage is the extended-key-usage shape of a certificate.
type Usage int

const (
	// UsageServer is for TLS listeners.
	UsageServer Usage = iota
	// UsageClient is for mTLS clients.
	UsageClient
	// UsageBoth is for components that both listen and dial.
	UsageBoth
)

// Validity defaults and file names. Keep these in sync with docs/08.
const (
	DefaultCATTL   = 10 * 365 * 24 * time.Hour
	DefaultCertTTL = 90 * 24 * time.Hour

	CAFile    = "ca.crt"
	CAKeyFile = "ca.key"
	CertFile  = "tls.crt"
	KeyFile   = "tls.key"

	// MinTLSVersion is the minimum accepted protocol version. TLS 1.3 only:
	// every component is a Go binary from this repo, so there is no legacy peer
	// justifying 1.2 and 1.3 removes the downgrade surface entirely.
	MinTLSVersion = tls.VersionTLS13
)

// Errors returned by this package; match with errors.Is.
var (
	ErrNoPEM             = errors.New("pki: no PEM block found")
	ErrNotCA             = errors.New("pki: certificate is not a CA")
	ErrExpired           = errors.New("pki: certificate has expired")
	ErrNotYetValid       = errors.New("pki: certificate is not valid yet")
	ErrWrongUsage        = errors.New("pki: certificate has the wrong extended key usage")
	ErrUntrustedCA       = errors.New("pki: certificate is not signed by the trusted CA")
	ErrHostnameMismatch  = errors.New("pki: certificate does not match the requested server name")
	ErrMissingCert       = errors.New("pki: TLS certificate is required")
	ErrMissingCA         = errors.New("pki: CA certificate is required")
	ErrMissingServerName = errors.New("pki: client TLS requires a ServerName (empty disables hostname verification)")
	ErrNoSigningKey      = errors.New("pki: CA has no signing key (verify-only CA cannot issue)")
)

// CertFiles are the paths of an issued certificate, its key, and the CA bundle
// that verifies it.
type CertFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// CA is a loaded certificate authority.
type CA struct {
	Cert     *x509.Certificate
	CertPEM  []byte
	KeyPEM   []byte
	CertFile string
	KeyFile  string
	signer   crypto.Signer
}

// CAOptions configures InitCA.
type CAOptions struct {
	CommonName   string
	Organization string
	TTL          time.Duration
}

// InitCA creates a new ECDSA P-256 CA and writes <dir>/ca.crt (0644) and
// <dir>/ca.key (0600).
func InitCA(dir string, opts CAOptions) (*CA, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("pki: CA directory is required")
	}
	if opts.CommonName == "" {
		opts.CommonName = "fass-cluster-ca"
	}
	if opts.Organization == "" {
		opts.Organization = "FASS"
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultCATTL
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		// Tolerate a few minutes of clock skew between operator host and cluster.
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(opts.TTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	keyPEM, err := encodeSignerKey(key)
	if err != nil {
		return nil, err
	}
	certFile := filepath.Join(dir, CAFile)
	keyFile := filepath.Join(dir, CAKeyFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("pki: create CA directory: %w", err)
	}
	if err := os.WriteFile(certFile, encodeCert(cert), 0o644); err != nil {
		return nil, fmt.Errorf("pki: write CA certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("pki: write CA key: %w", err)
	}
	return &CA{
		Cert:     cert,
		CertPEM:  encodeCert(cert),
		KeyPEM:   keyPEM,
		CertFile: certFile,
		KeyFile:  keyFile,
		signer:   key,
	}, nil
}

// LoadCA loads a CA certificate and (optionally) its signing key from files. An
// empty keyFile yields a verify-only CA, which is what production data-plane
// components use.
func LoadCA(certFile, keyFile string) (*CA, error) {
	if strings.TrimSpace(certFile) == "" {
		return nil, ErrMissingCA
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA certificate %s: %w", certFile, err)
	}
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load CA certificate %s: %w", certFile, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%w: %s", ErrNotCA, certFile)
	}
	ca := &CA{Cert: cert, CertPEM: encodeCert(cert), CertFile: certFile, KeyFile: keyFile}
	if keyFile != "" {
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("pki: read CA key %s: %w", keyFile, err)
		}
		signer, err := ParsePrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("pki: load CA key %s: %w", keyFile, err)
		}
		ca.KeyPEM = keyPEM
		ca.signer = signer
	}
	return ca, nil
}

// CertRequest describes one component certificate.
type CertRequest struct {
	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP
	Usage        Usage
	TTL          time.Duration
}

// Issued is a certificate plus its private key, in memory.
type Issued struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
	Key     crypto.Signer
}

// Issue signs a component certificate.
func (ca *CA) Issue(req CertRequest) (*Issued, error) {
	if ca.signer == nil {
		return nil, ErrNoSigningKey
	}
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, errors.New("pki: certificate common name is required")
	}
	if req.TTL <= 0 {
		req.TTL = DefaultCertTTL
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate certificate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.CommonName, Organization: req.Organization},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(req.TTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
	}
	switch req.Usage {
	case UsageServer:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case UsageClient:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case UsageBoth:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("pki: unknown usage %d", req.Usage)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.signer)
	if err != nil {
		return nil, fmt.Errorf("pki: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse issued certificate: %w", err)
	}
	keyPEM, err := encodeSignerKey(key)
	if err != nil {
		return nil, err
	}
	return &Issued{CertPEM: encodeCert(cert), KeyPEM: keyPEM, Cert: cert, Key: key}, nil
}

// IssueServer issues a server-auth certificate for the given names/IPs and
// writes tls.crt/tls.key into dir.
func (ca *CA) IssueServer(dns []string, ips []net.IP, ttl time.Duration, dir string) (CertFiles, error) {
	cn := "fass-server"
	if len(dns) > 0 && dns[0] != "" {
		cn = dns[0]
	} else if len(ips) > 0 && ips[0] != nil {
		cn = ips[0].String()
	}
	issued, err := ca.Issue(CertRequest{
		CommonName:  cn,
		DNSNames:    dns,
		IPAddresses: ips,
		Usage:       UsageServer,
		TTL:         ttl,
	})
	if err != nil {
		return CertFiles{}, err
	}
	return ca.writeFiles(dir, issued)
}

// IssueClient issues a client-auth certificate for a component identity.
func (ca *CA) IssueClient(identity string, ttl time.Duration, dir string) (CertFiles, error) {
	issued, err := ca.Issue(CertRequest{
		CommonName: identity,
		Usage:      UsageClient,
		TTL:        ttl,
	})
	if err != nil {
		return CertFiles{}, err
	}
	return ca.writeFiles(dir, issued)
}

func (ca *CA) writeFiles(dir string, issued *Issued) (CertFiles, error) {
	if strings.TrimSpace(dir) == "" {
		return CertFiles{}, errors.New("pki: output directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return CertFiles{}, fmt.Errorf("pki: create certificate directory: %w", err)
	}
	certFile := filepath.Join(dir, CertFile)
	keyFile := filepath.Join(dir, KeyFile)
	if err := os.WriteFile(certFile, issued.CertPEM, 0o644); err != nil {
		return CertFiles{}, fmt.Errorf("pki: write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, issued.KeyPEM, 0o600); err != nil {
		return CertFiles{}, fmt.Errorf("pki: write key: %w", err)
	}
	return CertFiles{CertFile: certFile, KeyFile: keyFile, CAFile: ca.CertFile}, nil
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

// ServerConfig builds a TLS listener config. requireClient enables mandatory
// client-certificate verification against clientCAFile (mTLS). TLS 1.3 minimum.
//
// The returned config keeps Certificates populated (so a caller can wrap
// GetCertificate for hot reload without surprises) and never enables insecure
// cipher suites.
func ServerConfig(certFile, keyFile, clientCAFile string, requireClient bool) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: --tls-cert and --tls-key are required", ErrMissingCert)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("pki: load server key pair (%s, %s): %w", certFile, keyFile, err)
	}
	cfg := &tls.Config{
		MinVersion:   MinTLSVersion,
		Certificates: []tls.Certificate{cert},
	}
	if requireClient {
		if clientCAFile == "" {
			return nil, fmt.Errorf("%w: --tls-ca is required with --require-mtls", ErrMissingCA)
		}
		pool, err := loadCertPool(clientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientConfig builds a TLS client config. serverName MUST be non-empty: an
// empty ServerName makes Go skip hostname verification, which would turn mTLS
// into decoration. A client certificate is added when certFile/keyFile are set;
// they may be empty for the server-auth-only migration phase.
func ClientConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	if strings.TrimSpace(serverName) == "" {
		return nil, ErrMissingServerName
	}
	if caFile == "" {
		return nil, fmt.Errorf("%w: --ca-cert is required to verify peers", ErrMissingCA)
	}
	pool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: MinTLSVersion,
		RootCAs:    pool,
		ServerName: serverName,
	}
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("%w: both --tls-cert and --tls-key are required for client authentication", ErrMissingCert)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("pki: load client key pair (%s, %s): %w", certFile, keyFile, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadCertPool(file string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA bundle %s: %w", file, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("pki: CA bundle %s contains no certificates", file)
	}
	return pool, nil
}

// ---------------------------------------------------------------------------
// Expiry / rotation
// ---------------------------------------------------------------------------

// NotAfter returns the NotAfter of the first certificate in certPEM.
func NotAfter(certPEM []byte) (time.Time, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// RenewalWindow returns how early a certificate should be renewed: one third of
// its lifetime, capped at 24 h and floored at 5 minutes.
func RenewalWindow(certPEM []byte) (time.Duration, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return 0, err
	}
	return renewalWindow(cert), nil
}

// renewalWindow is RenewalWindow for an already-parsed certificate.
func renewalWindow(cert *x509.Certificate) time.Duration {
	if cert == nil {
		return 24 * time.Hour
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	window := lifetime / 3
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if window < 5*time.Minute {
		window = 5 * time.Minute
	}
	return window
}

// ShouldRenew reports whether the certificate is inside its renewal window.
func ShouldRenew(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Until(cert.NotAfter) <= renewalWindow(cert)
}

// ExpiresWithin reports whether cert expires within d.
func ExpiresWithin(cert *x509.Certificate, d time.Duration) bool {
	if cert == nil {
		return true
	}
	return time.Until(cert.NotAfter) <= d
}

// IsExpired reports whether cert is past NotAfter.
func IsExpired(cert *x509.Certificate) bool {
	return cert == nil || time.Now().After(cert.NotAfter)
}

// ---------------------------------------------------------------------------
// Verification / actionable errors
// ---------------------------------------------------------------------------

// VerifyOptions narrows certificate verification.
type VerifyOptions struct {
	Usage   Usage
	DNSName string
	Now     time.Time
}

// VerifyChain validates leafPEM against caPEM (chain, validity, usage, host).
func VerifyChain(leafPEM, caPEM []byte, opts VerifyOptions) (*x509.Certificate, error) {
	leaf, err := ParseCertificate(leafPEM)
	if err != nil {
		return nil, err
	}
	ca, err := ParseCertificate(caPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   keyUsages(opts.Usage),
		DNSName:     opts.DNSName,
	}); err != nil {
		return nil, ExplainCertificateError(err, leaf, ca, now)
	}
	return leaf, nil
}

func keyUsages(u Usage) []x509.ExtKeyUsage {
	switch u {
	case UsageServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case UsageClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
}

// ExplainCertificateError turns stdlib verification errors into an
// operator-actionable message: expired certificate, unknown CA (wrong cluster),
// hostname mismatch.
func ExplainCertificateError(err error, leaf, ca *x509.Certificate, now time.Time) error {
	if err == nil {
		return nil
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.IncompatibleUsage {
		return fmt.Errorf("%w: certificate %q is not valid for the required purpose (client vs server auth); issue the correct certificate type",
			ErrWrongUsage, certName(invalid.Cert))
	}
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		cert := invalid.Cert
		if cert == nil {
			cert = leaf
		}
		when := "unknown"
		if cert != nil {
			when = cert.NotAfter.UTC().Format(time.RFC3339)
		}
		return fmt.Errorf("%w: peer certificate %q expired at %s (now %s); renew/re-enroll it against the cluster CA (docs/08-operations.md, TLS rotation)",
			ErrExpired, certName(cert), when, now.UTC().Format(time.RFC3339))
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return fmt.Errorf("%w: peer certificate was not signed by the configured CA %q (wrong cluster or stale CA bundle)",
			ErrUntrustedCA, certName(ca))
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return fmt.Errorf("%w: certificate SANs %v do not include %q",
			ErrHostnameMismatch, hostname.Certificate.DNSNames, hostname.Host)
	}
	if leaf != nil && now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: peer certificate %q expired at %s", ErrExpired, certName(leaf), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if leaf != nil && now.Before(leaf.NotBefore) {
		return fmt.Errorf("%w: peer certificate %q is valid only from %s", ErrNotYetValid, certName(leaf), leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	return fmt.Errorf("pki: certificate verification failed: %w", err)
}

// ExplainTLSHandshakeError adds actionable hints (plaintext peer, rejected
// certificate) to a raw handshake error.
func ExplainTLSHandshakeError(err error, peer string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "first record does not look like a TLS handshake"),
		strings.Contains(msg, "server gave HTTP response to HTTPS client"),
		strings.Contains(msg, "tls: oversized record"):
		return fmt.Errorf("pki: %s is speaking plaintext HTTP, not TLS; enable TLS on that component, or during a mixed-mode rollout use --agent-tls=auto: %w", peer, err)
	case strings.Contains(msg, "remote error: tls: bad certificate"),
		strings.Contains(msg, "remote error: tls: certificate required"),
		strings.Contains(msg, "remote error: tls: unknown certificate authority"):
		return fmt.Errorf("pki: %s rejected our certificate; check the CA bundle and client certificate: %w", peer, err)
	case strings.Contains(msg, "certificate has expired"),
		strings.Contains(msg, "expired or is not yet valid"):
		return fmt.Errorf("%w: peer certificate is expired/not yet valid; renew/re-enroll it against the cluster CA (docs/08-operations.md, TLS rotation): %w", ErrExpired, err)
	case strings.Contains(msg, "certificate signed by unknown authority"),
		strings.Contains(msg, "certificate is not trusted"):
		return fmt.Errorf("%w: %s: %v (check --ca-cert)", ErrUntrustedCA, peer, err)
	case strings.Contains(msg, "ServerName"):
		return err
	}
	return fmt.Errorf("pki: TLS handshake with %s failed: %w", peer, err)
}

func certName(c *x509.Certificate) string {
	if c == nil {
		return "<unknown>"
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------

// ParseCertificate parses the first CERTIFICATE PEM block.
func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePrivateKey parses an EC/PKCS#8 private key PEM block.
func ParsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoPEM
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("pki: unsupported private key format (want PKCS#8 or EC)")
}

// EncodeCertificatePEM exposes the PEM encoder for callers writing certs.
func EncodeCertificatePEM(cert *x509.Certificate) []byte { return encodeCert(cert) }

// EncodePrivateKeyPEM exposes the PEM encoder for callers writing keys.
func EncodePrivateKeyPEM(key crypto.Signer) ([]byte, error) { return encodeSignerKey(key) }

// Fingerprint returns a short SHA-256 fingerprint for logs (never key material).
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum[:8])
}

func encodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func encodeSignerKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}
	return serial, nil
}
