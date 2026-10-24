// Package authz verifies S3 request signatures locally using the HMAC key
// material the coordinator returns, and evaluates authorisation decisions with a
// short-lived cache.
//
// The split mirrors docs/04-services.md §5.1: the coordinator hands the gateway
// a principal plus the HMAC key for an access key id ("gateway verifies,
// coordinator authorises"). Signature verification therefore needs no
// coordinator round trip on the hot path; only access-key resolution and
// authorisation decisions do, and both are cached for at most 60 s.
package authz

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// Sentinel errors returned by the verifier. The S3 layer maps them to the XML
// error taxonomy in docs/05 §7.
var (
	// ErrUnsigned means the request carried no credentials at all. Callers may
	// treat it as anonymous and let the ACL layer decide.
	ErrUnsigned = errors.New("authz: request is not signed")
	// ErrAccessDenied means authentication succeeded but authorisation did not.
	ErrAccessDenied = errors.New("authz: access denied")
	// ErrPrincipalUnknown means the access key could not be resolved.
	ErrPrincipalUnknown = errors.New("authz: unknown access key")
)

// Identity is an authenticated caller plus the signature facts the S3 layer
// needs (notably streaming-payload verification material).
type Identity struct {
	Principal  contract.Principal
	AccessKey  string
	Presigned  bool
	SignedTime time.Time
	// Streaming is non-nil for aws-chunked request bodies; it must be handed to
	// sigv4.NewChunkedReader.
	Streaming *sigv4.StreamingMeta
	// Anonymous is true for unauthenticated requests that were allowed through
	// (the zero principal).
	Anonymous bool
}

// Options configures the verifier.
type Options struct {
	// ClockSkew bounds signature age. Defaults to 15 minutes.
	ClockSkew time.Duration
	// KeyTTL is how long resolved access keys are cached. Defaults to 60 s and
	// is clamped to that maximum (docs/07 §1.1: "the gateway caches hmac_key
	// for ≤ 60 s").
	KeyTTL time.Duration
	// DecisionTTL is how long authorisation decisions are cached. Defaults to
	// 15 s and is clamped to 60 s.
	DecisionTTL time.Duration
	// PresignTTL caps presigned URL lifetimes. Defaults to 7 days.
	PresignTTL time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

const (
	defaultKeyTTL      = 60 * time.Second
	maxKeyTTL          = 60 * time.Second
	defaultDecisionTTL = 15 * time.Second
	maxDecisionTTL     = 60 * time.Second
)

// Verifier authenticates and authorises S3 requests.
type Verifier struct {
	authz contract.Authorizer
	opts  Options

	mu        sync.Mutex
	creds     map[string]cachedCredential
	decisions map[string]cachedDecision
}

type cachedCredential struct {
	principal contract.Principal
	secret    string
	expires   time.Time
}

type cachedDecision struct {
	decision contract.Decision
	expires  time.Time
}

// New returns a Verifier backed by authz.
func New(a contract.Authorizer, opts Options) *Verifier {
	if opts.ClockSkew <= 0 {
		opts.ClockSkew = 15 * time.Minute
	}
	if opts.KeyTTL <= 0 || opts.KeyTTL > maxKeyTTL {
		opts.KeyTTL = defaultKeyTTL
	}
	if opts.DecisionTTL <= 0 || opts.DecisionTTL > maxDecisionTTL {
		opts.DecisionTTL = defaultDecisionTTL
	}
	if opts.PresignTTL <= 0 {
		opts.PresignTTL = 7 * 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Verifier{
		authz:     a,
		opts:      opts,
		creds:     make(map[string]cachedCredential),
		decisions: make(map[string]cachedDecision),
	}
}

// Now returns the verifier's clock.
func (v *Verifier) Now() time.Time { return v.opts.Now().UTC() }

// Authenticate identifies the caller and verifies the request signature locally.
//
// It returns ErrUnsigned when the request carries no credentials; callers decide
// whether anonymous access is permitted for the requested operation.
func (v *Verifier) Authenticate(ctx context.Context, r *http.Request) (Identity, error) {
	opts := sigv4.Options{
		ClockSkew:        v.opts.ClockSkew,
		Now:              v.opts.Now,
		MaxPresignExpiry: v.opts.PresignTTL,
	}
	keys := v.keyProvider(ctx)

	q := r.URL.Query()
	switch {
	case q.Get("X-Amz-Algorithm") != "":
		verified, err := sigv4.VerifyPresigned(ctx, r, keys, opts)
		if err != nil {
			return Identity{}, err
		}
		principal, err := v.principal(ctx, verified.AccessKeyID)
		if err != nil {
			return Identity{}, err
		}
		return Identity{
			Principal:  principal,
			AccessKey:  verified.AccessKeyID,
			Presigned:  true,
			SignedTime: verified.SignedTime,
		}, nil

	case strings.HasPrefix(r.Header.Get("Authorization"), sigv4.Algorithm+" "):
		verified, err := sigv4.VerifyHeader(ctx, r, keys, opts)
		if err != nil {
			return Identity{}, err
		}
		principal, err := v.principal(ctx, verified.AccessKeyID)
		if err != nil {
			return Identity{}, err
		}
		return Identity{
			Principal:  principal,
			AccessKey:  verified.AccessKeyID,
			SignedTime: verified.SignedTime,
			Streaming:  verified.Streaming,
		}, nil

	case strings.HasPrefix(r.Header.Get("Authorization"), sigv4.AlgorithmV2+" "),
		q.Get("AWSAccessKeyId") != "":
		auth, err := sigv4.ParseV2(r)
		if err != nil {
			return Identity{}, err
		}
		secret, err := v.secret(ctx, auth.AccessKeyID)
		if err != nil {
			return Identity{}, err
		}
		if _, err := sigv4.VerifyV2(r, secret, v.opts.Now().UTC(), v.opts.ClockSkew); err != nil {
			return Identity{}, err
		}
		principal, err := v.principal(ctx, auth.AccessKeyID)
		if err != nil {
			return Identity{}, err
		}
		return Identity{
			Principal:  principal,
			AccessKey:  auth.AccessKeyID,
			Presigned:  auth.Presigned,
			SignedTime: v.opts.Now().UTC(),
		}, nil

	default:
		return Identity{}, ErrUnsigned
	}
}

// Anonymous returns the principal used for unsigned requests.
func Anonymous() contract.Principal {
	return contract.Principal{Groups: []string{"AllUsers"}}
}

// Authorize evaluates the request against the coordinator's policy chain,
// caching the decision for a short TTL.
func (v *Verifier) Authorize(ctx context.Context, id Identity, action contract.Action, res contract.Resource, cond map[string]string) error {
	if res.Region == "" {
		res.Region = contract.DefaultRegion
	}
	rc := contract.RequestContext{
		Principal: id.Principal,
		Action:    action,
		Resource:  res,
		Now:       v.opts.Now().UTC(),
		Condition: cond,
	}

	key := decisionKey(rc)
	now := v.opts.Now()
	v.mu.Lock()
	if c, ok := v.decisions[key]; ok && now.Before(c.expires) {
		v.mu.Unlock()
		if c.decision.Allowed {
			return nil
		}
		return denyError(c.decision)
	}
	v.mu.Unlock()

	dec, err := v.authz.Authorize(ctx, rc)
	if err != nil {
		return fmt.Errorf("authz: authorize %s on %s: %w", action, res.CRN(), err)
	}

	v.mu.Lock()
	if len(v.decisions) > 8192 {
		// Bound the cache; a full sweep is cheaper than an unbounded map.
		v.decisions = make(map[string]cachedDecision)
	}
	v.decisions[key] = cachedDecision{decision: dec, expires: now.Add(v.opts.DecisionTTL)}
	v.mu.Unlock()

	if !dec.Allowed {
		return denyError(dec)
	}
	return nil
}

func denyError(d contract.Decision) error {
	reason := d.Reason
	if reason == "" {
		reason = "no matching allow statement"
	}
	return fmt.Errorf("%w: %s", ErrAccessDenied, reason)
}

// keyProvider adapts the cached access-key lookup to sigv4's KeyProvider.
func (v *Verifier) keyProvider(ctx context.Context) sigv4.KeyProvider {
	return func(ctx context.Context, accessKeyID string) (string, error) {
		return v.secret(ctx, accessKeyID)
	}
}

// secret returns the HMAC secret for an access key, caching it briefly.
func (v *Verifier) secret(ctx context.Context, accessKeyID string) (string, error) {
	v.mu.Lock()
	if c, ok := v.creds[accessKeyID]; ok && v.opts.Now().Before(c.expires) {
		v.mu.Unlock()
		return c.secret, nil
	}
	v.mu.Unlock()

	principal, secret, err := v.authz.VerifySignature(ctx, accessKeyID)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrPrincipalUnknown, accessKeyID, err)
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("%w: empty hmac key for %s", ErrPrincipalUnknown, accessKeyID)
	}

	v.mu.Lock()
	if len(v.creds) > 4096 {
		v.creds = make(map[string]cachedCredential)
	}
	v.creds[accessKeyID] = cachedCredential{
		principal: principal,
		secret:    string(secret),
		expires:   v.opts.Now().Add(v.opts.KeyTTL),
	}
	v.mu.Unlock()

	return string(secret), nil
}

// principal returns the cached principal for an access key id.
func (v *Verifier) principal(ctx context.Context, accessKeyID string) (contract.Principal, error) {
	if _, err := v.secret(ctx, accessKeyID); err != nil {
		return contract.Principal{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.creds[accessKeyID]
	if !ok {
		return contract.Principal{}, fmt.Errorf("%w: %s", ErrPrincipalUnknown, accessKeyID)
	}
	return c.principal, nil
}

// InvalidateAccessKey drops cached credentials for an access key (used on key
// rotation / revocation events).
func (v *Verifier) InvalidateAccessKey(accessKeyID string) {
	v.mu.Lock()
	delete(v.creds, accessKeyID)
	v.mu.Unlock()
}

// InvalidateDecisions clears the authorisation decision cache.
func (v *Verifier) InvalidateDecisions() {
	v.mu.Lock()
	v.decisions = make(map[string]cachedDecision)
	v.mu.Unlock()
}

func decisionKey(rc contract.RequestContext) string {
	var b strings.Builder
	b.WriteString(rc.Principal.AccessKeyID)
	b.WriteByte('|')
	b.WriteString(string(rc.Principal.TenantID))
	b.WriteByte('|')
	b.WriteString(string(rc.Action))
	b.WriteByte('|')
	b.WriteString(rc.Resource.CRN())
	// Conditions affect the decision (prefix, max-keys, acl, ...): include them
	// deterministically.
	if len(rc.Condition) > 0 {
		keys := make([]string, 0, len(rc.Condition))
		for k := range rc.Condition {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('|')
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(rc.Condition[k])
			b.WriteByte(';')
		}
	}
	return b.String()
}

// RequestID generates a random request id for logs and response headers. UUIDv4
// formatting keeps it recognisable to operators.
func RequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[pos] = '-'
			pos++
		}
		out[pos] = hex[c>>4]
		out[pos+1] = hex[c&0x0f]
		pos += 2
	}
	return string(out)
}
