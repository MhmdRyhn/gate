package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/auth/sso"
	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/service"
)

func init() { gin.SetMode(gin.TestMode) }

type fakeAuthn map[string]*domain.Principal

func (f fakeAuthn) Authenticate(_ context.Context, raw string) (*domain.Principal, error) {
	if p, ok := f[raw]; ok {
		return p, nil
	}
	return nil, domain.ErrInvalidToken
}

func TestAuthorizationMiddleware(t *testing.T) {
	staff := &domain.Principal{UserID: uuid.New(), Kind: domain.UserKindInternal, Permissions: domain.NewPermissionSet(rbac.UsersRead)}
	vendor := &domain.Principal{UserID: uuid.New(), Kind: domain.UserKindPublic, PublicTypes: []string{"customer", "vendor"},
		Permissions: domain.NewPermissionSet(rbac.UsersRead)}
	customer := &domain.Principal{UserID: uuid.New(), Kind: domain.UserKindPublic, PublicTypes: []string{"customer"}}
	authn := authenticate(fakeAuthn{"staff": staff, "vendor": vendor, "customer": customer}, errorWriter{log: zap.NewNop()})

	r := gin.New()
	r.Use(requestMeta(), securityHeaders())
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	r.GET("/any", authn, ok)
	r.GET("/admin", authn, RequireKind(domain.UserKindInternal), RequirePermissions(rbac.UsersRead), ok)
	r.GET("/admin/write", authn, RequireKind(domain.UserKindInternal), RequirePermissions(rbac.UsersRead, rbac.UsersCreate), ok)
	r.GET("/app", authn, RequireKind(domain.UserKindPublic), ok)
	r.GET("/app/vendor", authn, RequireKind(domain.UserKindPublic), RequirePublicType("vendor"), ok)

	cases := []struct {
		path, token string
		want        int
	}{
		{"/any", "", http.StatusUnauthorized},
		{"/any", "bogus", http.StatusUnauthorized},
		{"/any", "customer", http.StatusOK},
		{"/admin", "staff", http.StatusOK},
		{"/admin/write", "staff", http.StatusForbidden},
		{"/admin", "vendor", http.StatusForbidden}, // public user holding the permission is still blocked
		{"/app", "staff", http.StatusForbidden},
		{"/app", "customer", http.StatusOK},
		{"/app/vendor", "customer", http.StatusForbidden},
		{"/app/vendor", "vendor", http.StatusOK},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s as %q: status %d, want %d (%s)", tc.path, tc.token, rec.Code, tc.want, rec.Body)
		}
		if rec.Code >= 400 {
			var p Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Status != rec.Code || p.Code == "" || p.RequestID == "" {
				t.Errorf("%s: not a problem+json body: %s", tc.path, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
				t.Errorf("%s: content-type %q", tc.path, ct)
			}
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: security headers missing", tc.path)
		}
	}
}

func TestRequestIDPropagation(t *testing.T) {
	r := gin.New()
	r.Use(requestMeta())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "trace-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "trace-123" {
		t.Error("valid incoming request ID not reused")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "bad id\n<script>")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if _, err := uuid.Parse(rec.Header().Get("X-Request-ID")); err != nil {
		t.Error("malformed request ID not replaced")
	}
}

// --- SSO flow ------------------------------------------------------------------

type fakeProvider struct{ gotVerifier, gotNonce string }

func (p *fakeProvider) Name() string { return "fake" }
func (p *fakeProvider) AuthCodeURL(state, nonce, challenge string) string {
	return "https://idp.example/authorize?" + url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}}.Encode()
}
func (p *fakeProvider) Exchange(_ context.Context, code, verifier, nonce string) (*sso.Identity, error) {
	p.gotVerifier, p.gotNonce = verifier, nonce
	return &sso.Identity{Subject: "sub-1", Email: "a@example.com", EmailVerified: true}, nil
}

type fakeSignIn struct{ got *sso.Identity }

func (f *fakeSignIn) SignIn(_ context.Context, provider string, id *sso.Identity) (*service.TokenPair, error) {
	f.got = id
	return &service.TokenPair{AccessToken: "at", RefreshToken: "rt", AccessTokenExpiresAt: time.Now().Add(time.Minute), RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestSSOFlow(t *testing.T) {
	prov := &fakeProvider{}
	signIn := &fakeSignIn{}
	reg := sso.NewRegistry(sso.Registration{Provider: prov, Policy: sso.Policy{Kind: domain.UserKindPublic}})
	h, err := NewSSOHandler(reg, signIn, config.AuthConfig{SSOStateKey: config.Secret(strings.Repeat("k", 32))}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(requestMeta())
	r.GET("/sso/:provider/start", h.start)
	r.GET("/sso/:provider/callback", h.callback)

	// Start: redirect with state, nonce and S256 challenge; state cookie set.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sso/fake/start", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start: %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	cookie := rec.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || state == "" {
		t.Fatalf("insecure state cookie or missing state: %+v", cookie)
	}

	callback := func(q string, withCookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/sso/fake/callback?"+q, nil)
		if withCookie {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	if rec := callback("code=c&state="+state, false); rec.Code != http.StatusBadRequest {
		t.Errorf("callback without cookie: %d", rec.Code)
	}
	if rec := callback("code=c&state=forged", true); rec.Code != http.StatusBadRequest {
		t.Errorf("callback with wrong state: %d", rec.Code)
	}
	rec = callback("code=c&state="+url.QueryEscape(state), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	if prov.gotNonce != loc.Query().Get("nonce") || prov.gotVerifier == "" {
		t.Error("nonce/PKCE verifier not passed to the provider")
	}
	if signIn.got == nil || signIn.got.Provider != "fake" {
		t.Error("identity not forwarded with provider name")
	}

	if rec := httptest.NewRecorder(); true {
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sso/unknown/start", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("unknown provider: %d", rec.Code)
		}
	}
}

func TestSSOHandlerDisabledWithoutProviders(t *testing.T) {
	h, err := NewSSOHandler(sso.NewRegistry(), nil, config.AuthConfig{}, zap.NewNop())
	if err != nil || h != nil {
		t.Errorf("expected nil handler, got %v, %v", h, err)
	}
	reg := sso.NewRegistry(sso.Registration{Provider: &fakeProvider{}})
	if _, err := NewSSOHandler(reg, nil, config.AuthConfig{SSOStateKey: "short"}, zap.NewNop()); err == nil {
		t.Error("short SSO_STATE_KEY accepted")
	}
}
