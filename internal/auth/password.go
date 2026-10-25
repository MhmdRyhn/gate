// Package auth contains credential primitives: password hashing, signed
// access tokens (JWT), JWKS publication and opaque refresh tokens. It holds
// no business rules.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Password policy, following NIST SP 800-63B: length matters, composition
// rules do not. The maximum bounds hashing cost per request.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	errMalformedHash    = errors.New("malformed password hash")
)

// ValidatePassword enforces the password length policy.
func ValidatePassword(pw string) error {
	switch n := utf8.RuneCountInString(pw); {
	case n < MinPasswordLength:
		return ErrPasswordTooShort
	case n > MaxPasswordLength:
		return ErrPasswordTooLong
	}
	return nil
}

// Argon2Params are the Argon2id cost parameters.
type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params is OWASP's recommended minimum for Argon2id
// (19 MiB, 2 iterations, 1 lane). Raise them as hardware allows; existing
// hashes are upgraded transparently on the next successful login.
var DefaultArgon2Params = Argon2Params{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// PasswordHasher hashes and verifies passwords with Argon2id, encoded in the
// PHC string format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>.
//
// The number of concurrent hash operations is bounded so a burst of logins
// cannot exhaust memory (each operation allocates MemoryKiB).
type PasswordHasher struct {
	params Argon2Params
	sem    chan struct{}
	dummy  func() string
}

// NewPasswordHasher returns a hasher using params.
func NewPasswordHasher(params Argon2Params) *PasswordHasher {
	h := &PasswordHasher{params: params, sem: make(chan struct{}, 2*runtime.NumCPU())}
	h.dummy = sync.OnceValue(func() string {
		s, _ := h.Hash("timing-equaliser-password")
		return s
	})
	return h
}

// Hash returns the PHC-encoded Argon2id hash of pw.
func (h *PasswordHasher) Hash(pw string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := h.derive(pw, salt, h.params)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.MemoryKiB, h.params.Iterations, h.params.Parallelism,
		b64(salt), b64(key)), nil
}

// Verify reports whether pw matches the encoded hash, and whether the hash
// should be re-computed because it uses weaker parameters than configured.
func (h *PasswordHasher) Verify(encoded, pw string) (match, needsRehash bool) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false
	}
	got := h.derive(pw, salt, p)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, p != h.params
}

// VerifyDummy spends the same time as a real verification. Call it when no
// account matches, so response timing does not reveal which accounts exist.
func (h *PasswordHasher) VerifyDummy(pw string) {
	h.Verify(h.dummy(), pw)
}

func (h *PasswordHasher) derive(pw string, salt []byte, p Argon2Params) []byte {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return argon2.IDKey([]byte(pw), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
}

// decodeHash parses a PHC string. Parameters are capped so a tampered hash
// in the database cannot make verification consume unbounded resources.
func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	if p.MemoryKiB > 1<<20 || p.Iterations > 20 || p.Parallelism == 0 || p.Parallelism > 16 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	p.SaltLength, p.KeyLength = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
