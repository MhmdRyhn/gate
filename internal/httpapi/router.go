package httpapi

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
	"github.com/MhmdRyhn/gate/internal/service"
)

// RouterDeps are the dependencies of the HTTP router.
type RouterDeps struct {
	Config config.HTTPConfig
	App    config.AppConfig
	Auth   config.AuthConfig
	Log    *zap.Logger
	Authn  *service.AuthService
	Health repository.HealthChecker
	AuthH  *AuthHandler
	AdminH *AdminHandler
	SSOH   *SSOHandler // nil when SSO is not configured
}

// NewRouter builds the gin engine and is the authorization map of the API:
// each group and route declares who may call it.
func NewRouter(d RouterDeps) (*gin.Engine, error) {
	if d.App.Env != "development" {
		gin.SetMode(gin.ReleaseMode)
	}
	binding.EnableDecoderDisallowUnknownFields = true
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterTagNameFunc(jsonFieldName) // report "full_name", not "FullName"
	}

	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.RemoveExtraSlash = true
	// Only listed proxies may set the client IP via X-Forwarded-For.
	if err := r.SetTrustedProxies(d.Config.TrustedProxies); err != nil {
		return nil, fmt.Errorf("HTTP_TRUSTED_PROXIES: %w", err)
	}
	if len(d.Config.TrustedProxies) == 0 {
		_ = r.SetTrustedProxies(nil)
	}

	r.Use(requestMeta(), recovery(d.Log), accessLog(d.Log), securityHeaders(), bodyLimit(d.Config.MaxBodyBytes))
	if len(d.Config.CORSAllowedOrigins) > 0 {
		r.Use(cors.New(cors.Config{
			AllowOrigins:  d.Config.CORSAllowedOrigins,
			AllowMethods:  []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete},
			AllowHeaders:  []string{"Authorization", "Content-Type", "X-Request-ID"},
			ExposeHeaders: []string{"X-Request-ID", "Retry-After"},
			MaxAge:        12 * time.Hour,
			// Bearer tokens, not cookies: credentials mode is not needed.
			AllowCredentials: false,
		}))
	}
	r.NoRoute(func(c *gin.Context) { writeProblem(c, http.StatusNotFound, "not_found", "route not found") })
	r.NoMethod(func(c *gin.Context) {
		writeProblem(c, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})

	// Operational endpoints.
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/readyz", func(c *gin.Context) {
		if err := d.Health.Ping(c.Request.Context()); err != nil {
			writeProblem(c, http.StatusServiceUnavailable, "not_ready", "database unavailable")
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/.well-known/jwks.json", d.AuthH.jwks)

	ew := errorWriter{log: d.Log}
	authn := authenticate(d.Authn, ew)
	limiter := rateLimit(newIPLimiter(d.Auth.RateLimitPerMinute, d.Auth.RateLimitBurst))
	v1 := r.Group("/v1")

	// Unauthenticated.
	a := v1.Group("/auth")
	a.POST("/login", limiter, d.AuthH.login)
	a.POST("/refresh", limiter, d.AuthH.refresh)
	a.POST("/logout", d.AuthH.logout)
	if d.Auth.PublicRegistrationEnabled {
		a.POST("/register", limiter, d.AuthH.register)
		a.GET("/register/types", d.AuthH.registrationTypes)
	}
	if d.SSOH != nil {
		a.GET("/sso/:provider/start", limiter, d.SSOH.start)
		a.GET("/sso/:provider/callback", limiter, d.SSOH.callback)
	}

	// Any signed-in user.
	me := v1.Group("/me", authn)
	me.GET("", d.AuthH.me)
	me.POST("/password", d.AuthH.changePassword)
	me.POST("/logout-all", d.AuthH.logoutAll)

	// Public application API: only public users. Add the application's
	// routes here; restrict by type with RequirePublicType("vendor") and, if
	// the business needs it, by permission with RequirePermissions(...).
	_ = v1.Group("/app", authn, RequireKind(domain.UserKindPublic))

	// Internal (staff) API: only internal users, each route permission-gated.
	adm := v1.Group("/admin", authn, RequireKind(domain.UserKindInternal))
	adm.GET("/permissions", RequirePermissions(rbac.RolesRead), d.AdminH.listPermissions)
	adm.GET("/public-types", RequirePermissions(rbac.RolesRead), d.AdminH.listPublicTypes)

	adm.GET("/users", RequirePermissions(rbac.UsersRead), d.AdminH.listUsers)
	adm.POST("/users", RequirePermissions(rbac.UsersCreate), d.AdminH.createUser)
	adm.GET("/users/:id", RequirePermissions(rbac.UsersRead), d.AdminH.getUser)
	adm.PATCH("/users/:id", RequirePermissions(rbac.UsersUpdate), d.AdminH.updateUser)
	adm.PUT("/users/:id/roles", RequirePermissions(rbac.UsersAssignRoles), d.AdminH.setUserRoles)
	adm.PUT("/users/:id/public-types", RequirePermissions(rbac.UsersUpdate), d.AdminH.setUserPublicTypes)

	adm.GET("/roles", RequirePermissions(rbac.RolesRead), d.AdminH.listRoles)
	adm.POST("/roles", RequirePermissions(rbac.RolesManage), d.AdminH.createRole)
	adm.GET("/roles/:id", RequirePermissions(rbac.RolesRead), d.AdminH.getRole)
	adm.PATCH("/roles/:id", RequirePermissions(rbac.RolesManage), d.AdminH.updateRole)
	adm.DELETE("/roles/:id", RequirePermissions(rbac.RolesManage), d.AdminH.deleteRole)

	adm.GET("/audit-events", RequirePermissions(rbac.AuditRead), d.AdminH.listAudit)

	return r, nil
}

func jsonFieldName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "-" || name == "" {
		return f.Name
	}
	return name
}
