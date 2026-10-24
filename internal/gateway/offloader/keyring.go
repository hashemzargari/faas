package offloader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/crypto"
)

// KeyringProvider supplies the tenant keyring used to wrap and unwrap file keys.
// The production implementation reads per-tenant seeds from the gateway key
// service / KMIP; the static provider below covers dev mode and tests.
type KeyringProvider interface {
	KeyringFor(ctx context.Context, tenant contract.TenantID) (*crypto.Keyring, error)
}

// StaticKeyrings is a KeyringProvider backed by an in-memory seed map, with an
// optional default seed applied to tenants without their own seed.
//
// The default seed exists for single-tenant dev deployments (docs/03 §3.2
// "single-key" mode); production gateways set per-tenant seeds.
type StaticKeyrings struct {
	defaultSeed []byte
	seeds       map[contract.TenantID][]byte

	mu    sync.Mutex
	rings map[contract.TenantID]*crypto.Keyring
}

// NewStaticKeyrings builds a provider. defaultSeed may be nil when every tenant
// has an explicit seed.
func NewStaticKeyrings(defaultSeed []byte, seeds map[contract.TenantID][]byte) (*StaticKeyrings, error) {
	if len(defaultSeed) > 0 && len(defaultSeed) < 16 {
		return nil, fmt.Errorf("offloader: default key seed must be at least 16 bytes")
	}
	cp := make(map[contract.TenantID][]byte, len(seeds))
	for t, s := range seeds {
		if len(s) < 16 {
			return nil, fmt.Errorf("offloader: key seed for tenant %q must be at least 16 bytes", t)
		}
		cp[t] = append([]byte(nil), s...)
	}
	return &StaticKeyrings{
		defaultSeed: append([]byte(nil), defaultSeed...),
		seeds:       cp,
		rings:       make(map[contract.TenantID]*crypto.Keyring),
	}, nil
}

// KeyringFor returns (and caches) the keyring for a tenant.
func (s *StaticKeyrings) KeyringFor(_ context.Context, tenant contract.TenantID) (*crypto.Keyring, error) {
	if tenant == "" {
		return nil, fmt.Errorf("offloader: empty tenant id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if kr, ok := s.rings[tenant]; ok {
		return kr, nil
	}
	seed, ok := s.seeds[tenant]
	if !ok {
		if len(s.defaultSeed) == 0 {
			return nil, fmt.Errorf("offloader: no key seed configured for tenant %q", tenant)
		}
		seed = s.defaultSeed
	}
	kr, err := crypto.NewKeyring(string(tenant), seed)
	if err != nil {
		return nil, fmt.Errorf("offloader: derive keyring for tenant %q: %w", tenant, err)
	}
	s.rings[tenant] = kr
	return kr, nil
}

// GenerateSeed returns a cryptographically random 32-byte tenant seed, used by
// dev-mode bootstrap and tests.
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("offloader: generate seed: %w", err)
	}
	return seed, nil
}

// ParseSeed decodes a hex- or base64-less seed string (hex expected).
func ParseSeed(s string) ([]byte, error) {
	seed, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("offloader: seed must be hex: %w", err)
	}
	if len(seed) < 16 {
		return nil, fmt.Errorf("offloader: seed must be at least 16 bytes")
	}
	return seed, nil
}
