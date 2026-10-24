// Package crypto implements FASS's payload encryption.
//
// Design invariants (docs/03-data-plane.md §3):
//   - Encryption happens BEFORE erasure coding, so repair never needs a key.
//   - A random File Key per object version is wrapped by the tenant KEK; only
//     the wrapped form ever reaches the coordinator.
//   - Each chunk gets its own key derived from the File Key, and each frame
//     within a chunk has a random nonce plus AAD binding it to its exact
//     location. Moving a shard to another object/chunk therefore fails
//     authentication instead of silently decrypting.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// FileKeySize is 32 bytes: AES-256, matching Cubbit's documented AES-256.
	FileKeySize = 32
	// DefaultFrameSize is 1 MiB: large enough for throughput, small enough that
	// a range read does not have to buffer a whole 16 MiB chunk.
	DefaultFrameSize = 1 << 20
	// MaxFrameSize bounds memory per frame.
	MaxFrameSize = 8 << 20

	chunkMagic   = "FASSENC1"
	chunkVersion = 1

	// chunkHeaderSize = magic(8) + version(1) + reserved(3) + frameSize(4) + frameCount(4) + plaintextLen(8)
	chunkHeaderSize = 28
)

var (
	ErrKeyMismatch   = errors.New("crypto: key fingerprint mismatch")
	ErrAuthFailed    = errors.New("crypto: authentication failed (wrong key or tampered data)")
	ErrMalformed     = errors.New("crypto: malformed ciphertext")
	ErrFrameTooLarge = errors.New("crypto: frame size out of range")
)

// FileKey is the random per-object-version data key.
type FileKey struct{ raw [FileKeySize]byte }

// NewFileKey generates a fresh random File Key.
func NewFileKey() (FileKey, error) {
	var k FileKey
	if _, err := rand.Read(k.raw[:]); err != nil {
		return FileKey{}, fmt.Errorf("crypto: generate file key: %w", err)
	}
	return k, nil
}

// FromBytes reconstructs a FileKey (used after unwrapping).
func FromBytes(b []byte) (FileKey, error) {
	if len(b) != FileKeySize {
		return FileKey{}, fmt.Errorf("crypto: file key must be %d bytes, got %d", FileKeySize, len(b))
	}
	var k FileKey
	copy(k.raw[:], b)
	return k, nil
}

// Bytes returns the raw key material. Callers must not retain it.
func (k FileKey) Bytes() []byte { return k.raw[:] }

// Zero overwrites the key material.
func (k *FileKey) Zero() { clear(k.raw[:]) }

// Keyring holds one tenant's key seed and derives the KEK and fingerprint.
// A Keyring is immutable and safe for concurrent use.
type Keyring struct {
	tenantID    string
	kek         []byte
	fingerprint [8]byte
}

// NewKeyring derives the tenant KEK from its seed.
//
//	KEK         = HKDF(seed, salt=tenantID, info="fass/kek/v1", 32)
//	fingerprint = HKDF(seed, salt=tenantID, info="fass/keyfp/v1", 8)
func NewKeyring(tenantID string, seed []byte) (*Keyring, error) {
	if len(seed) < 16 {
		return nil, fmt.Errorf("crypto: tenant seed too short (%d bytes)", len(seed))
	}
	if tenantID == "" {
		return nil, errors.New("crypto: empty tenant id")
	}
	kek, err := hkdf(seed, []byte(tenantID), "fass/kek/v1", 32)
	if err != nil {
		return nil, err
	}
	fp, err := hkdf(seed, []byte(tenantID), "fass/keyfp/v1", 8)
	if err != nil {
		return nil, err
	}
	kr := &Keyring{tenantID: tenantID, kek: kek}
	copy(kr.fingerprint[:], fp)
	return kr, nil
}

// Fingerprint identifies the key generation. It is stored alongside the
// wrapped key in the manifest so a gateway configured with the wrong KMS key
// fails with a precise ErrKeyMismatch instead of an opaque GCM auth failure:
// callers compare manifest.Fingerprint against Keyring.Fingerprint().
func (k *Keyring) Fingerprint() [8]byte { return k.fingerprint }

// WrapKey encrypts a File Key with the tenant KEK.
// Output layout: nonce(12) || ciphertext(48) where the plaintext is 32 bytes.
// AAD binds the wrapped key to the tenant.
func (k *Keyring) WrapKey(fk FileKey) ([]byte, error) {
	aead, err := newGCM(k.kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: wrap nonce: %w", err)
	}
	out := aead.Seal(nonce, nonce, fk.raw[:], []byte(k.tenantID))
	return out, nil
}

// UnwrapKey decrypts a File Key and verifies it belongs to this Keyring.
func (k *Keyring) UnwrapKey(wrapped []byte) (FileKey, error) {
	aead, err := newGCM(k.kek)
	if err != nil {
		return FileKey{}, err
	}
	ns := aead.NonceSize()
	if len(wrapped) != ns+FileKeySize+aead.Overhead() {
		return FileKey{}, fmt.Errorf("%w: wrapped key is %d bytes", ErrMalformed, len(wrapped))
	}
	plain, err := aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte(k.tenantID))
	if err != nil {
		return FileKey{}, ErrAuthFailed
	}
	fk, err := FromBytes(plain)
	clear(plain)
	if err != nil {
		// A wrong keyring is caught by GCM above; reaching here means the
		// wrapped blob was structurally wrong.
		return FileKey{}, err
	}
	return fk, nil
}

// ChunkAAD binds a frame's ciphertext to its exact position in the object.
type ChunkAAD struct {
	TenantID   string
	Bucket     string
	Key        string
	VersionID  string
	ChunkIndex int
	FrameIndex int
	FrameLen   int // plaintext bytes in this frame
}

// aadBytes produces a deterministic 32-byte commitment over the AAD fields.
// Hashing keeps the AAD compact while binding every field exactly.
func (a ChunkAAD) aadBytes() []byte {
	h := sha256.New()
	var buf [8]byte
	writeStr := func(s string) {
		binary.BigEndian.PutUint32(buf[:4], uint32(len(s)))
		h.Write(buf[:4])
		h.Write([]byte(s))
	}
	writeUint := func(v uint64) {
		binary.BigEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}
	writeStr(a.TenantID)
	writeStr(a.Bucket)
	writeStr(a.Key)
	writeStr(a.VersionID)
	writeUint(uint64(a.ChunkIndex))
	writeUint(uint64(a.FrameIndex))
	writeUint(uint64(a.FrameLen))
	return h.Sum(nil)
}

// ChunkEncryptor encrypts/decrypts chunks with one File Key.
type ChunkEncryptor struct {
	fileKey   FileKey
	frameSize int
}

// NewChunkEncryptor returns an encryptor for one object version's File Key.
func NewChunkEncryptor(fk FileKey, frameSize int) (*ChunkEncryptor, error) {
	if frameSize == 0 {
		frameSize = DefaultFrameSize
	}
	if frameSize < 4096 || frameSize > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d", ErrFrameTooLarge, frameSize)
	}
	return &ChunkEncryptor{fileKey: fk, frameSize: frameSize}, nil
}

// FrameSize reports the configured plaintext frame size.
func (e *ChunkEncryptor) FrameSize() int { return e.frameSize }

// chunkKey derives the per-chunk key:
//
//	HKDF(fileKey, salt=chunkIndex(BE64), info="fass/chunk/v1", 32)
func (e *ChunkEncryptor) chunkKey(chunkIndex int) ([]byte, error) {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], uint64(chunkIndex))
	return hkdf(e.fileKey.raw[:], salt[:], "fass/chunk/v1", 32)
}

// EncryptChunk returns the framed ciphertext of one chunk.
//
// Layout:
//
//	magic(8) version(1) reserved(3) frameSize(4) frameCount(4) plaintextLen(8)
//	then frameCount × [ nonce(12) || GCM ciphertext(frameLen+16) ]
func (e *ChunkEncryptor) EncryptChunk(plaintext []byte, aad ChunkAAD) ([]byte, error) {
	key, err := e.chunkKey(aad.ChunkIndex)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(plaintext) == 0 {
		out := make([]byte, chunkHeaderSize)
		copy(out, chunkMagic)
		out[8] = chunkVersion
		binary.BigEndian.PutUint32(out[12:], uint32(e.frameSize))
		binary.BigEndian.PutUint32(out[16:], 0)
		binary.BigEndian.PutUint64(out[20:], 0)
		return out, nil
	}

	frameCount := (len(plaintext) + e.frameSize - 1) / e.frameSize
	outLen := chunkHeaderSize + len(plaintext) + frameCount*aead.Overhead() + frameCount*aead.NonceSize()
	out := make([]byte, 0, outLen)

	hdr := make([]byte, chunkHeaderSize)
	copy(hdr, chunkMagic)
	hdr[8] = chunkVersion
	binary.BigEndian.PutUint32(hdr[12:], uint32(e.frameSize))
	binary.BigEndian.PutUint32(hdr[16:], uint32(frameCount))
	binary.BigEndian.PutUint64(hdr[20:], uint64(len(plaintext)))
	out = append(out, hdr...)

	for i := 0; i < frameCount; i++ {
		start := i * e.frameSize
		end := start + e.frameSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		frame := plaintext[start:end]

		fa := aad
		fa.FrameIndex = i
		fa.FrameLen = len(frame)

		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("crypto: frame nonce: %w", err)
		}
		out = append(out, nonce...)
		out = aead.Seal(out, nonce, frame, fa.aadBytes())
	}
	return out, nil
}

// DecryptChunk reverses EncryptChunk and verifies the header against the AAD it
// was encrypted with.
func (e *ChunkEncryptor) DecryptChunk(ciphertext []byte, aad ChunkAAD) ([]byte, error) {
	if len(ciphertext) < chunkHeaderSize {
		return nil, ErrMalformed
	}
	if string(ciphertext[:8]) != chunkMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	if ciphertext[8] != chunkVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrMalformed, ciphertext[8])
	}
	frameSize := int(binary.BigEndian.Uint32(ciphertext[12:]))
	frameCount := int(binary.BigEndian.Uint32(ciphertext[16:]))
	plaintextLen := int(binary.BigEndian.Uint64(ciphertext[20:]))
	if frameSize < 4096 || frameSize > MaxFrameSize {
		return nil, fmt.Errorf("%w: header frame size %d", ErrMalformed, frameSize)
	}
	if plaintextLen == 0 {
		if frameCount != 0 {
			return nil, ErrMalformed
		}
		return []byte{}, nil
	}
	if frameCount != (plaintextLen+frameSize-1)/frameSize {
		return nil, fmt.Errorf("%w: frame count %d inconsistent with length %d", ErrMalformed, frameCount, plaintextLen)
	}

	key, err := e.chunkKey(aad.ChunkIndex)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, plaintextLen)
	off := chunkHeaderSize
	for i := 0; i < frameCount; i++ {
		flen := frameSize
		if i == frameCount-1 {
			flen = plaintextLen - frameSize*(frameCount-1)
		}
		need := aead.NonceSize() + flen + aead.Overhead()
		if off+need > len(ciphertext) {
			return nil, fmt.Errorf("%w: truncated at frame %d", ErrMalformed, i)
		}
		nonce := ciphertext[off : off+aead.NonceSize()]
		body := ciphertext[off+aead.NonceSize() : off+need]
		off += need

		fa := aad
		fa.FrameIndex = i
		fa.FrameLen = flen

		frame, err := aead.Open(nil, nonce, body, fa.aadBytes())
		if err != nil {
			return nil, ErrAuthFailed
		}
		out = append(out, frame...)
	}
	if off != len(ciphertext) {
		return nil, fmt.Errorf("%w: trailing %d bytes", ErrMalformed, len(ciphertext)-off)
	}
	if len(out) != plaintextLen {
		return nil, fmt.Errorf("%w: decrypted %d bytes, want %d", ErrMalformed, len(out), plaintextLen)
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return aead, nil
}
