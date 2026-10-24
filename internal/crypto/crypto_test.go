package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// RFC 5869, Appendix A.1 (HKDF-SHA256, basic test case).
func TestHKDFRFC5869Vector(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	prk := hkdfExtract(salt, ikm)
	wantPRK := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	if got := hex.EncodeToString(prk); got != wantPRK {
		t.Fatalf("PRK = %s, want %s", got, wantPRK)
	}

	okm, err := hkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	wantOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(okm); got != wantOKM {
		t.Fatalf("OKM = %s, want %s", got, wantOKM)
	}
}

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	seed := bytes.Repeat([]byte{0x5a}, 32)
	kr, err := NewKeyring("tenant-1", seed)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestWrapUnwrap(t *testing.T) {
	kr := testKeyring(t)
	fk, err := NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := kr.WrapKey(fk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kr.UnwrapKey(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), fk.Bytes()) {
		t.Fatal("unwrapped key differs")
	}
}

func TestUnwrapWithWrongKeyringFails(t *testing.T) {
	kr := testKeyring(t)
	fk, _ := NewFileKey()
	wrapped, err := kr.WrapKey(fk)
	if err != nil {
		t.Fatal(err)
	}

	other, err := NewKeyring("tenant-1", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.UnwrapKey(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestUnwrapTamperedFails(t *testing.T) {
	kr := testKeyring(t)
	fk, _ := NewFileKey()
	wrapped, _ := kr.WrapKey(fk)
	wrapped[len(wrapped)-1] ^= 0xff
	if _, err := kr.UnwrapKey(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestFingerprintIsStable(t *testing.T) {
	a, b := testKeyring(t), testKeyring(t)
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("same seed must yield same fingerprint")
	}
	other, _ := NewKeyring("tenant-1", bytes.Repeat([]byte{0x11}, 32))
	if a.Fingerprint() == other.Fingerprint() {
		t.Fatal("different seeds must yield different fingerprints")
	}
}

func aad() ChunkAAD {
	return ChunkAAD{
		TenantID:   "tenant-1",
		Bucket:     "bkt",
		Key:        "path/to/object.bin",
		VersionID:  "11111111-2222-3333-4444-555555555555",
		ChunkIndex: 3,
	}
}

func TestChunkRoundTrip(t *testing.T) {
	const frame = 4096
	fk, _ := NewFileKey()
	enc, err := NewChunkEncryptor(fk, frame)
	if err != nil {
		t.Fatal(err)
	}

	sizes := []int{0, 1, 2, frame - 1, frame, frame + 1, 2 * frame, 2*frame + 37, 10*frame + 1}
	for _, n := range sizes {
		plain := make([]byte, n)
		if n > 0 {
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
		}
		ct, err := enc.EncryptChunk(plain, aad())
		if err != nil {
			t.Fatalf("n=%d encrypt: %v", n, err)
		}
		got, err := enc.DecryptChunk(ct, aad())
		if err != nil {
			t.Fatalf("n=%d decrypt: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("n=%d round trip mismatch", n)
		}
		// Ciphertext must actually differ from plaintext.
		if n > 0 && bytes.Equal(ct[chunkHeaderSize:], plain) {
			t.Fatalf("n=%d ciphertext contains plaintext", n)
		}
	}
}

func TestChunkTamperDetected(t *testing.T) {
	fk, _ := NewFileKey()
	enc, _ := NewChunkEncryptor(fk, 4096)
	plain := bytes.Repeat([]byte("A"), 5000)
	ct, err := enc.EncryptChunk(plain, aad())
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-5] ^= 0x01
	if _, err := enc.DecryptChunk(ct, aad()); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

// TestAADBindsLocation is the substitution-attack guard: the same ciphertext
// must not decrypt under a different chunk index, object, or version.
func TestAADBindsLocation(t *testing.T) {
	fk, _ := NewFileKey()
	enc, _ := NewChunkEncryptor(fk, 4096)
	plain := bytes.Repeat([]byte("B"), 3000)
	ct, err := enc.EncryptChunk(plain, aad())
	if err != nil {
		t.Fatal(err)
	}

	mutations := []func(ChunkAAD) ChunkAAD{
		func(a ChunkAAD) ChunkAAD { a.ChunkIndex++; return a },
		func(a ChunkAAD) ChunkAAD { a.Bucket = "other"; return a },
		func(a ChunkAAD) ChunkAAD { a.Key = "other.bin"; return a },
		func(a ChunkAAD) ChunkAAD { a.VersionID = "deadbeef"; return a },
		func(a ChunkAAD) ChunkAAD { a.TenantID = "tenant-2"; return a },
	}
	for i, mut := range mutations {
		wrong := mut(aad())
		// Chunk-index mutation also changes the derived key, which is fine: the
		// point is that it must fail.
		dec, _ := NewChunkEncryptor(fk, 4096)
		if _, err := dec.DecryptChunk(ct, wrong); err == nil {
			t.Fatalf("mutation %d: decryption should have failed", i)
		}
	}
}

func TestChunkTruncationDetected(t *testing.T) {
	fk, _ := NewFileKey()
	enc, _ := NewChunkEncryptor(fk, 4096)
	plain := bytes.Repeat([]byte("C"), 9000)
	ct, err := enc.EncryptChunk(plain, aad())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.DecryptChunk(ct[:len(ct)-3], aad()); err == nil {
		t.Fatal("truncated ciphertext must fail")
	}
	if _, err := enc.DecryptChunk(ct[:10], aad()); err == nil {
		t.Fatal("short header must fail")
	}
}

func TestChunkEncryptionIsRandomised(t *testing.T) {
	fk, _ := NewFileKey()
	enc, _ := NewChunkEncryptor(fk, 4096)
	plain := bytes.Repeat([]byte("D"), 100)
	a, _ := enc.EncryptChunk(plain, aad())
	b, _ := enc.EncryptChunk(plain, aad())
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext must differ (nonce reuse?)")
	}
}

func TestBadFrameSize(t *testing.T) {
	fk, _ := NewFileKey()
	if _, err := NewChunkEncryptor(fk, 16); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	if _, err := NewChunkEncryptor(fk, MaxFrameSize+1); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestShortSeedRejected(t *testing.T) {
	if _, err := NewKeyring("t", []byte{1, 2, 3}); err == nil {
		t.Fatal("short seed must be rejected")
	}
	if _, err := NewKeyring("", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("empty tenant must be rejected")
	}
}

func BenchmarkEncryptChunk16MiB(b *testing.B) {
	fk, _ := NewFileKey()
	enc, _ := NewChunkEncryptor(fk, DefaultFrameSize)
	plain := make([]byte, 16<<20)
	a := aad()
	b.SetBytes(int64(len(plain)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.EncryptChunk(plain, a); err != nil {
			b.Fatal(err)
		}
	}
}
