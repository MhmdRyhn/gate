package sso

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// FlowTTL bounds how long a user may take at the provider's login page.
const FlowTTL = 10 * time.Minute

// MinStateKeyLength is the minimum size of the state signing key.
const MinStateKeyLength = 32

// ErrInvalidState is returned when the callback's state cookie is missing,
// tampered, expired or does not match the request.
var ErrInvalidState = errors.New("invalid SSO state")

// FlowState is kept client-side, in a signed HttpOnly cookie, between the
// start and callback of a sign-in. Keeping it out of the database makes
// the flow stateless and horizontally scalable.
type FlowState struct {
	Provider     string    `json:"p"`
	State        string    `json:"s"` // CSRF protection (RFC 6749 §10.12)
	Nonce        string    `json:"n"` // ID token replay protection (OIDC)
	CodeVerifier string    `json:"v"` // PKCE (RFC 7636)
	ExpiresAt    time.Time `json:"e"`
}

// NewFlowState creates fresh random state, nonce and PKCE verifier.
func NewFlowState(provider string, now time.Time) (FlowState, error) {
	s, n, v := randomString(), randomString(), randomString()+randomString() // verifier: 86 chars
	if s == "" || n == "" || v == "" {
		return FlowState{}, errors.New("random source failed")
	}
	return FlowState{Provider: provider, State: s, Nonce: n, CodeVerifier: v, ExpiresAt: now.Add(FlowTTL)}, nil
}

// CodeChallenge returns the PKCE S256 challenge for the verifier.
func (f FlowState) CodeChallenge() string {
	sum := sha256.Sum256([]byte(f.CodeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StateCodec seals and opens FlowState with HMAC-SHA256. The payload is
// signed, not encrypted: it contains only one-time random values.
type StateCodec struct {
	key []byte
}

// NewStateCodec returns a codec using key (at least 32 bytes).
func NewStateCodec(key []byte) (*StateCodec, error) {
	if len(key) < MinStateKeyLength {
		return nil, errors.New("SSO_STATE_KEY must be at least 32 bytes")
	}
	return &StateCodec{key: key}, nil
}

// Seal encodes and signs f.
func (c *StateCodec) Seal(f FlowState) (string, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + c.sign(p), nil
}

// Open verifies and decodes a sealed state, rejecting expired ones.
func (c *StateCodec) Open(sealed string, now time.Time) (FlowState, error) {
	p, sig, ok := strings.Cut(sealed, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(c.sign(p))) {
		return FlowState{}, ErrInvalidState
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return FlowState{}, ErrInvalidState
	}
	var f FlowState
	if err := json.Unmarshal(payload, &f); err != nil || now.After(f.ExpiresAt) {
		return FlowState{}, ErrInvalidState
	}
	return f, nil
}

func (c *StateCodec) sign(p string) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("sso-state:" + p))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
