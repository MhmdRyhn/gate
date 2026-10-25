package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/auth/sso"
	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/service"
)

const ssoCookie = "__Host-sso_state"

// SSOSignIner completes a sign-in from a verified identity. Implemented by
// service.SSOService.
type SSOSignIner interface {
	SignIn(ctx context.Context, provider string, id *sso.Identity) (*service.TokenPair, error)
}

// SSOHandler implements the browser side of the OAuth 2.0 / OIDC
// authorization code flow with state, nonce and PKCE:
//
//	GET /v1/auth/sso/:provider/start     -> 302 to the provider
//	GET /v1/auth/sso/:provider/callback  -> verifies, signs in, returns tokens
//
// It is nil (and no routes are registered) when no provider is configured.
type SSOHandler struct {
	registry *sso.Registry
	codec    *sso.StateCodec
	signIn   SSOSignIner
	ew       errorWriter
	now      func() time.Time
}

// NewSSOHandler returns nil when no provider is registered. Otherwise it
// requires SSO_STATE_KEY.
func NewSSOHandler(registry *sso.Registry, signIn SSOSignIner, cfg config.AuthConfig, log *zap.Logger) (*SSOHandler, error) {
	if registry.Empty() {
		return nil, nil
	}
	codec, err := sso.NewStateCodec([]byte(cfg.SSOStateKey.Value()))
	if err != nil {
		return nil, err
	}
	return &SSOHandler{registry: registry, codec: codec, signIn: signIn, ew: errorWriter{log: log}, now: time.Now}, nil
}

func (h *SSOHandler) start(c *gin.Context) {
	reg, err := h.registry.Get(c.Param("provider"))
	if err != nil {
		writeProblem(c, http.StatusNotFound, "not_found", "unknown SSO provider")
		return
	}
	flow, err := sso.NewFlowState(reg.Provider.Name(), h.now())
	if err != nil {
		h.ew.write(c, err)
		return
	}
	sealed, err := h.codec.Seal(flow)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	// __Host- prefix: Secure, Path=/, no Domain — cannot be set by subdomains.
	// SameSite=Lax lets the cookie survive the top-level redirect back.
	http.SetCookie(c.Writer, &http.Cookie{
		Name: ssoCookie, Value: sealed, Path: "/", MaxAge: int(sso.FlowTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	c.Redirect(http.StatusFound, reg.Provider.AuthCodeURL(flow.State, flow.Nonce, flow.CodeChallenge()))
}

func (h *SSOHandler) callback(c *gin.Context) {
	providerName := c.Param("provider")
	reg, err := h.registry.Get(providerName)
	if err != nil {
		writeProblem(c, http.StatusNotFound, "not_found", "unknown SSO provider")
		return
	}
	// The state cookie is single-use: clear it whatever the outcome.
	http.SetCookie(c.Writer, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	if e := c.Query("error"); e != "" {
		writeProblem(c, http.StatusUnauthorized, "sso_denied", "the identity provider denied the sign-in")
		return
	}
	raw, err := c.Cookie(ssoCookie)
	if err != nil {
		writeProblem(c, http.StatusBadRequest, "invalid_state", "missing SSO state; restart the sign-in")
		return
	}
	flow, err := h.codec.Open(raw, h.now())
	if err != nil || flow.Provider != providerName ||
		subtle.ConstantTimeCompare([]byte(flow.State), []byte(c.Query("state"))) != 1 {
		writeProblem(c, http.StatusBadRequest, "invalid_state", "invalid SSO state; restart the sign-in")
		return
	}
	code := c.Query("code")
	if code == "" || len(code) > 2048 {
		writeProblem(c, http.StatusBadRequest, "invalid_request", "missing authorization code")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	identity, err := reg.Provider.Exchange(ctx, code, flow.CodeVerifier, flow.Nonce)
	if err != nil {
		h.ew.log.Warn("SSO code exchange failed", zap.String("provider", providerName), zap.Error(err))
		writeProblem(c, http.StatusUnauthorized, "sso_failed", "could not verify the identity provider response")
		return
	}
	identity.Provider = providerName
	pair, err := h.signIn.SignIn(c.Request.Context(), providerName, identity)
	if err != nil {
		if errors.Is(err, sso.ErrUnknownProvider) {
			writeProblem(c, http.StatusNotFound, "not_found", "unknown SSO provider")
			return
		}
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newTokenResponse(pair))
}
