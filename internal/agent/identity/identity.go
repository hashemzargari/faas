// Package identity manages the agent's persistent Ed25519 identity.
//
// docs/04-services.md §5.4: an agent announces a public key and is later
// identified by the hash of it; the key therefore has to survive restarts. The
// key lives on the data disk it serves, so moving the disk moves the identity
// with it. The private key is written with mode 0600 and never leaves the host.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyFilename  = "agent.key"
	dirPerm      = 0o700
	keyFilePerm  = 0o600
	pemBlockType = "PRIVATE KEY"
)

// Identity is the agent's long-lived key pair.
type Identity struct {
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	path       string
}

// LoadOrCreate loads the agent key from dir, generating one on first boot.
func LoadOrCreate(dir string) (*Identity, error) {
	if dir == "" {
		return nil, errors.New("identity: empty directory")
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("identity: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, keyFilename)

	raw, err := os.ReadFile(path)
	if err == nil {
		return parse(path, raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, block, keyFilePerm); err != nil {
		return nil, fmt.Errorf("identity: write key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("identity: install key: %w", err)
	}
	return &Identity{PublicKey: pub, privateKey: priv, path: path}, nil
}

func parse(path string, raw []byte) (*Identity, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemBlockType {
		return nil, fmt.Errorf("identity: %s is not a PEM private key", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s holds %T, want ed25519", path, key)
	}
	return &Identity{PublicKey: priv.Public().(ed25519.PublicKey), privateKey: priv, path: path}, nil
}

// Path is where the private key is stored.
func (i *Identity) Path() string { return i.path }

// PrivateKey returns the signing key (used by tests and by future mTLS
// certificate requests; the key itself never leaves the process).
func (i *Identity) PrivateKey() ed25519.PrivateKey { return i.privateKey }

// PublicKeyBase64 is the form the coordinator's announce request expects.
func (i *Identity) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(i.PublicKey)
}
