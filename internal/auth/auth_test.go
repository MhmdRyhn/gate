package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
)

func newIssuer(t *testing.T, kind string) (*TokenIssuer, string) {
	t.Helper()
	pemKey, _, err := GenerateKey(kind, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeySet(pemKey, "")
	if err != nil {
		t.Fatal(err)
	}
	return NewTokenIssuer(ks, "https://auth.test", "api", time.Minute), pemKey
}

func TestTokenRoundTrip(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa"} {
		iss, _ := newIssuer(t, kind)
		uid, sid := uuid.New(), uuid.New()
		tok, _, err := iss.Issue(uid, sid, domain.UserKindPublic)
		if err != nil {
			t.Fatal(err)
		}
		c, err := iss.Parse(tok)
		if err != nil || c.Subject != uid.String() || c.SessionID != sid.String() || c.Kind != domain.UserKindPublic {
			t.Errorf("%s: Parse = %+v, %v", kind, c, err)
		}
	}
}

func TestTokenRejected(t *testing.T) {
	iss, _ := newIssuer(t, "ed25519")
	tok, _, _ := iss.Issue(uuid.New(), uuid.New(), domain.UserKindInternal)

	other, _ := newIssuer(t, "ed25519")
	if _, err := other.Parse(tok); err == nil {
		t.Error("token accepted by a different key set")
	}

	wrongAud := NewTokenIssuer(iss.keys, iss.issuer, "other-api", time.Minute)
	if _, err := wrongAud.Parse(tok); err == nil {
		t.Error("token accepted for wrong audience")
	}

	later := NewTokenIssuer(iss.keys, iss.issuer, iss.audience, time.Minute)
	later.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := later.Parse(tok); err == nil {
		t.Error("expired token accepted")
	}

	// A correctly signed JWT without typ=at+jwt (e.g. an ID token) is rejected.
	k := iss.keys.Signing()
	idTok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": iss.issuer, "aud": iss.audience, "sub": uuid.NewString(), "sid": uuid.NewString(),
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	idTok.Header["kid"] = k.ID
	s, _ := idTok.SignedString(k.Private)
	if _, err := iss.Parse(s); err == nil {
		t.Error("token without typ=at+jwt accepted")
	}

	// alg=none and tampered payloads are rejected.
	parts := strings.Split(tok, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
	if _, err := iss.Parse(none + "." + parts[1] + "."); err == nil {
		t.Error("alg=none accepted")
	}
}

func TestKeyRotation(t *testing.T) {
	oldIss, oldPEM := newIssuer(t, "ed25519")
	tok, _, _ := oldIss.Issue(uuid.New(), uuid.New(), domain.UserKindInternal)

	newPEM, _, _ := GenerateKey("ed25519", 0)
	oldPub, err := PublicKeyPEM(oldPEM)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeySet(newPEM, oldPub)
	if err != nil {
		t.Fatal(err)
	}
	rotated := NewTokenIssuer(ks, oldIss.issuer, oldIss.audience, time.Minute)
	if _, err := rotated.Parse(tok); err != nil {
		t.Errorf("token signed by previous key rejected: %v", err)
	}
	if len(ks.JWKS().Keys) != 2 {
		t.Errorf("JWKS should publish current and previous key")
	}
}

// RFC 8037 appendix A.3 test vector for the Ed25519 JWK thumbprint.
func TestThumbprintRFC8037(t *testing.T) {
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if got := thumbprint(publicJWK(ed25519.PublicKey(x))); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Errorf("thumbprint = %s", got)
	}
}

func TestLoadKeySetRejectsWeakOrBadKeys(t *testing.T) {
	if _, err := LoadKeySet("not a key", ""); err == nil {
		t.Error("garbage accepted")
	}
	if _, _, err := GenerateKey("rsa", 1024); err == nil {
		t.Error("1024-bit RSA accepted")
	}
	pemKey, _, _ := GenerateKey("ed25519", 0)
	b64 := base64.StdEncoding.EncodeToString([]byte(pemKey))
	if _, err := LoadKeySet(b64, ""); err != nil {
		t.Errorf("base64 PEM rejected: %v", err)
	}
}

func TestPasswordHasher(t *testing.T) {
	h := NewPasswordHasher(Argon2Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Errorf("unexpected encoding %s", enc)
	}
	if ok, rehash := h.Verify(enc, "correct horse battery"); !ok || rehash {
		t.Errorf("Verify = %v, %v", ok, rehash)
	}
	if ok, _ := h.Verify(enc, "wrong horse battery"); ok {
		t.Error("wrong password accepted")
	}
	stronger := NewPasswordHasher(Argon2Params{MemoryKiB: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if ok, rehash := stronger.Verify(enc, "correct horse battery"); !ok || !rehash {
		t.Error("weaker hash should be flagged for rehash")
	}
	if ok, _ := h.Verify("$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "x"); ok {
		t.Error("absurd parameters accepted")
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("a", 129)) == nil {
		t.Error("length policy not enforced")
	}
	if err := ValidatePassword("১২৩৪৫৬৭৮৯০১২"); err != nil { // 12 runes, multi-byte
		t.Errorf("unicode password rejected: %v", err)
	}
}

func TestOpaqueToken(t *testing.T) {
	a, ha, _ := NewOpaqueToken()
	b, _, _ := NewOpaqueToken()
	if a == b || string(ha) != string(HashOpaqueToken(a)) {
		t.Error("opaque tokens broken")
	}
}
