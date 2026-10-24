package authz

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

type fakeAuthorizer struct {
	mu           sync.Mutex
	lookups      int
	decisions    int
	lastKey      string
	allowed      bool
	reason       string
	authorizeErr error
}

func (f *fakeAuthorizer) VerifySignature(ctx context.Context, accessKeyID string) (contract.Principal, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	f.lastKey = accessKeyID
	if accessKeyID != "AKIATEST" {
		return contract.Principal{}, nil, errors.New("unknown key")
	}
	return contract.Principal{
		AccessKeyID: "AKIATEST",
		TenantID:    "t1",
		ProjectID:   "p1",
	}, []byte("topsecret"), nil
}

func (f *fakeAuthorizer) Authorize(ctx context.Context, rc contract.RequestContext) (contract.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions++
	if f.authorizeErr != nil {
		return contract.Decision{}, f.authorizeErr
	}
	return contract.Decision{Allowed: f.allowed, Reason: f.reason}, nil
}

func (f *fakeAuthorizer) counts() (lookups, decisions int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups, f.decisions
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestVerifier(t *testing.T, auth *fakeAuthorizer) (*Verifier, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	return New(auth, Options{ClockSkew: 15 * time.Minute, Now: clk.now}), clk
}

func signedRequest(t *testing.T, clk *clock) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://s3.eu-west-1.amazonaws.com/bucket/key?list-type=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigv4.SignRequest(req, "AKIATEST", "topsecret", clk.now(), sigv4.EmptyStringSHA256); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestAuthenticateSigV4HeaderAndKeyCache(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	v, clk := newTestVerifier(t, auth)

	id, err := v.Authenticate(context.Background(), signedRequest(t, clk))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Principal.TenantID != "t1" || id.Principal.ProjectID != "p1" {
		t.Fatalf("principal = %+v", id.Principal)
	}
	if id.AccessKey != "AKIATEST" || id.Presigned {
		t.Fatalf("identity = %+v", id)
	}

	// A second request within the key TTL must not hit the coordinator again.
	if _, err := v.Authenticate(context.Background(), signedRequest(t, clk)); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
	if lookups, _ := auth.counts(); lookups != 1 {
		t.Fatalf("coordinator lookups = %d, want 1 (cached)", lookups)
	}

	// Past the TTL the key is resolved again.
	clk.advance(61 * time.Second)
	if _, err := v.Authenticate(context.Background(), signedRequest(t, clk)); err != nil {
		t.Fatalf("third Authenticate: %v", err)
	}
	if lookups, _ := auth.counts(); lookups != 2 {
		t.Fatalf("coordinator lookups = %d, want 2 after expiry", lookups)
	}
}

func TestAuthenticateRejectsTamperingAndUnsigned(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	v, clk := newTestVerifier(t, auth)

	req := signedRequest(t, clk)
	// Query parameters are covered by the signature even though they are not in
	// SignedHeaders, so adding one must invalidate the request.
	req.URL.RawQuery += "&evil=1"
	if _, err := v.Authenticate(context.Background(), req); !errors.Is(err, sigv4.ErrSignatureMismatch) {
		t.Fatalf("tampered error = %v, want signature mismatch", err)
	}

	unsigned, _ := http.NewRequest(http.MethodGet, "https://s3.eu-west-1.amazonaws.com/bucket/key", nil)
	if _, err := v.Authenticate(context.Background(), unsigned); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned error = %v, want ErrUnsigned", err)
	}
}

func TestAuthenticatePresigned(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	v, clk := newTestVerifier(t, auth)
	u, _ := url.Parse("https://s3.eu-west-1.amazonaws.com/bucket/key")
	if err := sigv4.SignURL(u, "AKIATEST", "topsecret", http.MethodGet, clk.now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	id, err := v.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("presigned Authenticate: %v", err)
	}
	if !id.Presigned {
		t.Fatal("identity not marked presigned")
	}
}

func TestAuthorizeDecisionCache(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	v, clk := newTestVerifier(t, auth)
	id := Identity{Principal: contract.Principal{AccessKeyID: "AKIATEST", TenantID: "t1", ProjectID: "p1"}, AccessKey: "AKIATEST"}
	res := contract.Resource{Kind: "object", TenantID: "t1", ProjectID: "p1", Bucket: "b", Key: "k"}

	for i := 0; i < 3; i++ {
		if err := v.Authorize(context.Background(), id, contract.ActionGetObject, res, nil); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	}
	if _, decisions := auth.counts(); decisions != 1 {
		t.Fatalf("coordinator decisions = %d, want 1 (cached)", decisions)
	}

	// A different action is a different decision.
	if err := v.Authorize(context.Background(), id, contract.ActionPutObject, res, nil); err != nil {
		t.Fatal(err)
	}
	if _, decisions := auth.counts(); decisions != 2 {
		t.Fatalf("decisions = %d, want 2 for a new action", decisions)
	}

	// Past the decision TTL the coordinator is consulted again.
	clk.advance(61 * time.Second)
	if err := v.Authorize(context.Background(), id, contract.ActionGetObject, res, nil); err != nil {
		t.Fatal(err)
	}
	if _, decisions := auth.counts(); decisions != 3 {
		t.Fatalf("decisions = %d, want 3 after expiry", decisions)
	}
}

func TestAuthorizeDeny(t *testing.T) {
	auth := &fakeAuthorizer{allowed: false, reason: "explicit deny in policy p-1"}
	v, _ := newTestVerifier(t, auth)
	id := Identity{Principal: contract.Principal{AccessKeyID: "AKIATEST", TenantID: "t1"}}
	res := contract.Resource{Kind: "bucket", TenantID: "t1", Bucket: "b"}
	err := v.Authorize(context.Background(), id, contract.ActionDeleteBucket, res, nil)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("error = %v, want ErrAccessDenied", err)
	}
	if !strings.Contains(err.Error(), "explicit deny") {
		t.Fatalf("deny reason lost: %v", err)
	}
}

func TestRequestIDUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := RequestID()
		if len(id) != 36 || id[14] != '4' {
			t.Fatalf("bad UUIDv4 %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}
