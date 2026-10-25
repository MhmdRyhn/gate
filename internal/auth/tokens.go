package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
)

// AccessTokenType is the JOSE "typ" header for access tokens (RFC 9068).
// Verifying it prevents other JWTs (e.g. ID tokens) being replayed as
// access tokens.
const AccessTokenType = "at+jwt"

// ErrInvalidToken is returned for any token that fails verification. The
// cause is deliberately not exposed to clients.
var ErrInvalidToken = errors.New("invalid token")

// AccessClaims are the claims of an access token. Registered claims follow
// RFC 7519 / RFC 9068; "sid" and "kind" are private claims.
type AccessClaims struct {
	jwt.RegisteredClaims
	// SessionID ("sid") ties the token to a session so it dies with it.
	SessionID string `json:"sid"`
	// Kind ("kind") is "internal" or "public". It is immutable per user,
	// so resource servers may use it for coarse routing decisions.
	Kind domain.UserKind `json:"kind"`
}

// TokenIssuer signs and verifies access tokens.
//
// Tokens carry identity only (who, which session, which kind). Roles and
// permissions are resolved from the database on each request, so changes
// take effect immediately. See docs/jwt.md.
type TokenIssuer struct {
	keys     *KeySet
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
}

// NewTokenIssuer returns an issuer for tokens valid for ttl.
func NewTokenIssuer(keys *KeySet, issuer, audience string, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{keys: keys, issuer: issuer, audience: audience, ttl: ttl, now: time.Now}
}

// TTL returns the configured access token lifetime.
func (t *TokenIssuer) TTL() time.Duration { return t.ttl }

// Issue signs an access token for the given user and session.
func (t *TokenIssuer) Issue(userID, sessionID uuid.UUID, kind domain.UserKind) (string, time.Time, error) {
	now := t.now().UTC()
	exp := now.Add(t.ttl)
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{t.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
		SessionID: sessionID.String(),
		Kind:      kind,
	}
	k := t.keys.Signing()
	tok := jwt.NewWithClaims(signingMethod(k.Algorithm), claims)
	tok.Header["typ"] = AccessTokenType
	tok.Header["kid"] = k.ID
	s, err := tok.SignedString(k.Private)
	return s, exp, err
}

// Parse verifies signature, header type, issuer, audience and time claims,
// and returns the claims. The key is selected by "kid" and must match the
// token's "alg", which rules out algorithm-confusion attacks.
func (t *TokenIssuer) Parse(raw string) (*AccessClaims, error) {
	var claims AccessClaims
	_, err := jwt.ParseWithClaims(raw, &claims, t.keyFunc,
		jwt.WithValidMethods([]string{AlgEdDSA, AlgRS256}),
		jwt.WithIssuer(t.issuer),
		jwt.WithAudience(t.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(t.now),
	)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, ErrInvalidToken
	}
	if _, err := uuid.Parse(claims.SessionID); err != nil {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (t *TokenIssuer) keyFunc(tok *jwt.Token) (any, error) {
	if typ, _ := tok.Header["typ"].(string); typ != AccessTokenType {
		return nil, ErrInvalidToken
	}
	kid, _ := tok.Header["kid"].(string)
	k, ok := t.keys.Lookup(kid)
	if !ok || tok.Method.Alg() != k.Algorithm {
		return nil, ErrInvalidToken
	}
	return k.Public, nil
}

// NewOpaqueToken returns a random 256-bit token (base64url) and the SHA-256
// hash to persist. Used for refresh tokens.
func NewOpaqueToken() (plain string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	return plain, HashOpaqueToken(plain), nil
}

// HashOpaqueToken returns the SHA-256 digest of an opaque token. A fast hash
// is appropriate because the token has 256 bits of entropy.
func HashOpaqueToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}
