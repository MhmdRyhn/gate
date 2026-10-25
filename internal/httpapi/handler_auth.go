package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/auth"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/service"
)

// AuthHandler serves sign-in, registration, token refresh, logout and the
// signed-in user's own endpoints (/v1/me).
type AuthHandler struct {
	auth  *service.AuthService
	users *service.UserService
	keys  *auth.KeySet
	ew    errorWriter
}

// NewAuthHandler wires an AuthHandler.
func NewAuthHandler(a *service.AuthService, u *service.UserService, keys *auth.KeySet, log *zap.Logger) *AuthHandler {
	return &AuthHandler{auth: a, users: u, keys: keys, ew: errorWriter{log: log}}
}

// login: POST /v1/auth/login — email or phone + password.
func (h *AuthHandler) login(c *gin.Context) {
	var req loginRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	pair, err := h.auth.Login(c.Request.Context(), req.Identifier, req.Password)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newTokenResponse(pair))
}

// register: POST /v1/auth/register — public self-registration.
func (h *AuthHandler) register(c *gin.Context) {
	var req registerRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	pair, err := h.auth.Register(c.Request.Context(), service.RegisterInput{
		Email: req.Email, Phone: req.Phone, FullName: req.FullName, Password: req.Password, Type: req.Type,
	})
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusCreated, newTokenResponse(pair))
}

// registrationTypes: GET /v1/auth/register/types — types open for sign-up.
func (h *AuthHandler) registrationTypes(c *gin.Context) {
	type item struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	items := []item{}
	for _, t := range rbac.PublicUserTypes {
		if t.SelfRegistration {
			items = append(items, item{t.Name, t.Description})
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "default": rbac.DefaultPublicType})
}

// refresh: POST /v1/auth/refresh — rotate the refresh token.
func (h *AuthHandler) refresh(c *gin.Context) {
	var req refreshRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	pair, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newTokenResponse(pair))
}

// logout: POST /v1/auth/logout — revoke the refresh token's session.
func (h *AuthHandler) logout(c *gin.Context) {
	var req refreshRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	if err := h.auth.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		h.ew.write(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// jwks: GET /.well-known/jwks.json — public keys for token verification.
func (h *AuthHandler) jwks(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, h.keys.JWKS())
}

// me: GET /v1/me — the signed-in user, roles and effective permissions.
func (h *AuthHandler) me(c *gin.Context) {
	p := principalFrom(c)
	d, err := h.users.Get(c.Request.Context(), p.UserID)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	perms := []string{}
	for _, perm := range p.Permissions.Sorted() {
		perms = append(perms, string(perm))
	}
	c.JSON(http.StatusOK, meResponse{userResponse: newUserDetailsResponse(d), SessionID: p.SessionID, Permissions: perms})
}

// changePassword: POST /v1/me/password — other sessions are signed out.
func (h *AuthHandler) changePassword(c *gin.Context) {
	var req changePasswordRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	if err := h.auth.ChangePassword(c.Request.Context(), principalFrom(c), req.CurrentPassword, req.NewPassword); err != nil {
		h.ew.write(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// logoutAll: POST /v1/me/logout-all — revoke every session of the user.
func (h *AuthHandler) logoutAll(c *gin.Context) {
	if err := h.auth.LogoutAll(c.Request.Context(), principalFrom(c)); err != nil {
		h.ew.write(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
