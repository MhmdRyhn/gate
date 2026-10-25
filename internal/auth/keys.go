package auth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Supported JWS algorithms. EdDSA (Ed25519) is the default: small keys,
// fast, no parameter pitfalls. RS256 is offered for consumers that lack
// EdDSA support.
const (
	AlgEdDSA = "EdDSA"
	AlgRS256 = "RS256"
)

const minRSABits = 2048

// Key is one asymmetric key with its JWS algorithm and key ID.
type Key struct {
	ID        string // RFC 7638 JWK thumbprint
	Algorithm string
	Private   crypto.Signer // nil for verification-only keys
	Public    crypto.PublicKey
}

// KeySet holds the current signing key and every key accepted for
// verification (the signing key plus older keys kept during rotation).
type KeySet struct {
	signing *Key
	verify  map[string]*Key
}

// LoadKeySet parses the PKCS#8 private signing key and an optional bundle of
// PEM public keys (PKIX) still accepted for verification. Both inputs may be
// PEM text or base64-encoded PEM, which is easier to pass in env vars.
func LoadKeySet(signingKey, verificationKeys string) (*KeySet, error) {
	der, err := firstPEM(signingKey, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("JWT signing key: %w", err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("JWT signing key: expected PKCS#8: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("JWT signing key: unsupported key type")
	}
	signing, err := newKey(signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("JWT signing key: %w", err)
	}

	ks := &KeySet{signing: signing, verify: map[string]*Key{signing.ID: signing}}
	if strings.TrimSpace(verificationKeys) == "" {
		return ks, nil
	}
	blocks, err := allPEM(verificationKeys, "PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("JWT verification keys: %w", err)
	}
	for _, der := range blocks {
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("JWT verification key: %w", err)
		}
		k, err := newKey(pub, nil)
		if err != nil {
			return nil, fmt.Errorf("JWT verification key: %w", err)
		}
		ks.verify[k.ID] = k
	}
	return ks, nil
}

// Signing returns the key used to sign new tokens.
func (ks *KeySet) Signing() *Key { return ks.signing }

// Lookup returns the verification key with the given ID.
func (ks *KeySet) Lookup(kid string) (*Key, bool) {
	k, ok := ks.verify[kid]
	return k, ok
}

// JWK is a public JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS is a JSON Web Key Set, served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public half of every verification key.
func (ks *KeySet) JWKS() JWKS {
	out := JWKS{Keys: []JWK{}}
	for _, k := range ks.verify {
		jwk := publicJWK(k.Public)
		jwk.Kid, jwk.Use, jwk.Alg = k.ID, "sig", k.Algorithm
		out.Keys = append(out.Keys, jwk)
	}
	return out
}

// GenerateKey creates a new PKCS#8 PEM private key ("ed25519" or "rsa").
func GenerateKey(kind string, rsaBits int) (pemText string, kid string, err error) {
	var signer crypto.Signer
	switch kind {
	case "ed25519":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		if rsaBits < minRSABits {
			return "", "", fmt.Errorf("RSA keys must be at least %d bits", minRSABits)
		}
		signer, err = rsa.GenerateKey(rand.Reader, rsaBits)
	default:
		return "", "", fmt.Errorf("unknown key type %q (want ed25519 or rsa)", kind)
	}
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", "", err
	}
	k, err := newKey(signer.Public(), signer)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), k.ID, nil
}

// PublicKeyPEM returns the PKIX PEM public key of a PKCS#8 private key, for
// publishing an old key in JWT_VERIFICATION_KEYS during rotation.
func PublicKeyPEM(privateKey string) (string, error) {
	der, err := firstPEM(privateKey, "PRIVATE KEY")
	if err != nil {
		return "", err
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", errors.New("unsupported key type")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), nil
}

func newKey(pub crypto.PublicKey, priv crypto.Signer) (*Key, error) {
	k := &Key{Private: priv, Public: pub}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		k.Algorithm = AlgEdDSA
	case *rsa.PublicKey:
		if p.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key must be at least %d bits", minRSABits)
		}
		k.Algorithm = AlgRS256
	default:
		return nil, fmt.Errorf("unsupported key type %T (want Ed25519 or RSA)", pub)
	}
	k.ID = thumbprint(publicJWK(pub))
	return k, nil
}

func publicJWK(pub crypto.PublicKey) JWK {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url(p)}
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", N: b64url(p.N.Bytes()), E: b64url(big.NewInt(int64(p.E)).Bytes())}
	}
	return JWK{}
}

// thumbprint computes the RFC 7638 JWK thumbprint: SHA-256 over the
// required members in lexicographic order, without whitespace.
func thumbprint(j JWK) string {
	var canonical string
	switch j.Kty {
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, j.Crv, j.X)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64url(sum[:])
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pemText accepts PEM directly or base64-encoded PEM.
func pemText(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if strings.Contains(s, "-----BEGIN") {
		return []byte(s), nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("expected PEM or base64-encoded PEM")
	}
	return b, nil
}

func allPEM(s, wantType string) ([][]byte, error) {
	data, err := pemText(s)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != wantType {
			return nil, fmt.Errorf("unexpected PEM block %q (want %q)", block.Type, wantType)
		}
		out = append(out, block.Bytes)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %q PEM block found", wantType)
	}
	return out, nil
}

func firstPEM(s, wantType string) ([]byte, error) {
	blocks, err := allPEM(s, wantType)
	if err != nil {
		return nil, err
	}
	return blocks[0], nil
}

// signingMethod maps our algorithm names to jwt-go signing methods.
func signingMethod(alg string) jwt.SigningMethod {
	if alg == AlgRS256 {
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodEdDSA
}
