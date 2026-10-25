package sso

import (
	"strings"
	"testing"
	"time"
)

func TestStateCodec(t *testing.T) {
	c, err := NewStateCodec([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	f, _ := NewFlowState("google", now)
	sealed, _ := c.Seal(f)

	got, err := c.Open(sealed, now)
	if err != nil || got.State != f.State || got.CodeVerifier != f.CodeVerifier {
		t.Fatalf("Open = %+v, %v", got, err)
	}
	if _, err := c.Open(sealed, now.Add(FlowTTL+time.Second)); err == nil {
		t.Error("expired state accepted")
	}
	if _, err := c.Open(sealed[:len(sealed)-2]+"xx", now); err == nil {
		t.Error("tampered state accepted")
	}
	other, _ := NewStateCodec([]byte(strings.Repeat("o", 32)))
	if _, err := other.Open(sealed, now); err == nil {
		t.Error("state from another key accepted")
	}
	if _, err := NewStateCodec([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}

func TestPKCEChallenge(t *testing.T) {
	// RFC 7636 appendix B.
	f := FlowState{CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
	if got := f.CodeChallenge(); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge = %s", got)
	}
	g, _ := NewFlowState("x", time.Now())
	if n := len(g.CodeVerifier); n < 43 || n > 128 {
		t.Errorf("verifier length %d outside RFC 7636 bounds", n)
	}
}
