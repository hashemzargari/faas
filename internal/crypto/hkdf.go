package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// HKDF-SHA256 (RFC 5869), implemented here rather than pulled from a module so
// the key schedule is auditable and dependency-free.
//
//	PRK      = HMAC-SHA256(salt, IKM)
//	T(i)     = HMAC-SHA256(PRK, T(i-1) || info || i)
//	OKM      = first L bytes of T(1) || T(2) || ...
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("crypto: invalid HKDF output length %d", length)
	}
	out := make([]byte, 0, length)
	var prev []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length], nil
}

// hkdf is the one-shot extract-and-expand form used by the key schedule.
func hkdf(secret, salt []byte, info string, length int) ([]byte, error) {
	return hkdfExpand(hkdfExtract(salt, secret), []byte(info), length)
}
