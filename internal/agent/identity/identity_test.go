package identity

import (
	"crypto/ed25519"
	"os"
	"testing"
)

func TestLoadOrCreatePersistsKey(t *testing.T) {
	dir := t.TempDir()
	id1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(id1.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d", len(id1.PublicKey))
	}
	if id1.PublicKeyBase64() == "" {
		t.Fatal("empty base64 public key")
	}

	fi, err := os.Stat(id1.Path())
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != keyFilePerm {
		t.Fatalf("key permissions = %o, want %o", perm, keyFilePerm)
	}

	id2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !id2.PublicKey.Equal(id1.PublicKey) {
		t.Fatal("public key changed across restart")
	}
	if id2.PrivateKey() == nil {
		t.Fatal("reloaded identity has no private key")
	}
}

func TestLoadOrCreateRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/"+keyFilename, []byte("not a pem key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("LoadOrCreate accepted a garbage key file")
	}
}
