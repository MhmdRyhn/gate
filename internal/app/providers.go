// Package app assembles the application with Google Wire. Provider sets are
// declared here; wire.go lists the injectors and wire_gen.go is generated:
//
//	go run github.com/google/wire/cmd/wire ./internal/app
package app

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/wire"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/MhmdRyhn/gate/internal/auth"
	"github.com/MhmdRyhn/gate/internal/auth/sso"
	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/httpapi"
	"github.com/MhmdRyhn/gate/internal/repository"
	"github.com/MhmdRyhn/gate/internal/repository/postgres"
	"github.com/MhmdRyhn/gate/internal/service"
)

// ConfigSet exposes the config sections as separate injectable values.
var ConfigSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "App", "HTTP", "Database", "Auth", "JWT"),
)

// RepositorySet binds the gorm implementations to the repository ports.
var RepositorySet = wire.NewSet(
	ProvideDatabase,
	postgres.NewUserRepository, wire.Bind(new(repository.UserRepository), new(*postgres.UserRepository)),
	postgres.NewRoleRepository, wire.Bind(new(repository.RoleRepository), new(*postgres.RoleRepository)),
	postgres.NewSessionRepository, wire.Bind(new(repository.SessionRepository), new(*postgres.SessionRepository)),
	postgres.NewIdentityRepository, wire.Bind(new(repository.IdentityRepository), new(*postgres.IdentityRepository)),
	postgres.NewAuditRepository, wire.Bind(new(repository.AuditRepository), new(*postgres.AuditRepository)),
	postgres.NewHealth, wire.Bind(new(repository.HealthChecker), new(*postgres.Health)),
)

// ServiceSet provides credential primitives and use-case services.
var ServiceSet = wire.NewSet(
	ProvideKeySet,
	ProvideTokenIssuer,
	ProvidePasswordHasher,
	ProvideSSORegistry,
	service.NewAuditor,
	service.NewAuthService,
	service.NewUserService,
	service.NewRoleService,
	service.NewSSOService,
	service.NewSeeder,
)

// HTTPSet provides handlers, the router and the server.
var HTTPSet = wire.NewSet(
	httpapi.NewAuthHandler,
	httpapi.NewAdminHandler,
	ProvideSSOHandler,
	ProvideRouter,
	httpapi.NewServer,
)

// ProvideDatabase opens the gorm connection pool.
func ProvideDatabase(ctx context.Context, cfg config.DatabaseConfig, log *zap.Logger) (*gorm.DB, func(), error) {
	return postgres.Open(ctx, cfg, log)
}

// ProvideKeySet loads the JWT signing and verification keys.
func ProvideKeySet(cfg config.JWTConfig) (*auth.KeySet, error) {
	return auth.LoadKeySet(cfg.SigningKey.Value(), cfg.VerificationKeys.Value())
}

// ProvideTokenIssuer builds the access token issuer.
func ProvideTokenIssuer(keys *auth.KeySet, jwtCfg config.JWTConfig, authCfg config.AuthConfig) *auth.TokenIssuer {
	return auth.NewTokenIssuer(keys, jwtCfg.Issuer, jwtCfg.Audience, authCfg.AccessTokenTTL)
}

// ProvidePasswordHasher returns the Argon2id hasher.
func ProvidePasswordHasher() *auth.PasswordHasher {
	return auth.NewPasswordHasher(auth.DefaultArgon2Params)
}

// ProvideSSORegistry lists the enabled SSO providers. None are integrated
// yet; register them here, e.g.:
//
//	google, err := oidcprovider.New(ctx, oidcprovider.Config{...}) // implements sso.Provider
//	return sso.NewRegistry(sso.Registration{
//		Provider: google,
//		Policy:   sso.Policy{Kind: domain.UserKindPublic, AllowSignup: true, SignupPublicType: rbac.PublicTypeCustomer, LinkVerifiedEmail: true},
//	}), nil
//
// See docs/sso.md.
func ProvideSSORegistry() (*sso.Registry, error) {
	return sso.NewRegistry(), nil
}

// ProvideSSOHandler returns nil when no SSO provider is registered.
func ProvideSSOHandler(reg *sso.Registry, svc *service.SSOService, cfg config.AuthConfig, log *zap.Logger) (*httpapi.SSOHandler, error) {
	return httpapi.NewSSOHandler(reg, svc, cfg, log)
}

// ProvideRouter builds the gin engine.
func ProvideRouter(appCfg config.AppConfig, httpCfg config.HTTPConfig, authCfg config.AuthConfig, log *zap.Logger,
	authSvc *service.AuthService, health repository.HealthChecker,
	authH *httpapi.AuthHandler, adminH *httpapi.AdminHandler, ssoH *httpapi.SSOHandler) (*gin.Engine, error) {
	return httpapi.NewRouter(httpapi.RouterDeps{
		Config: httpCfg, App: appCfg, Auth: authCfg, Log: log, Authn: authSvc, Health: health,
		AuthH: authH, AdminH: adminH, SSOH: ssoH,
	})
}

// Server is everything the `serve` command runs.
type Server struct {
	HTTP   *httpapi.Server
	Seeder *service.Seeder
	Auth   *service.AuthService
	Log    *zap.Logger
}

// Run optionally syncs the RBAC registry, starts the session purger and
// serves HTTP until ctx is cancelled.
func (s *Server) Run(ctx context.Context, syncRBAC bool, purgeEvery time.Duration) error {
	if syncRBAC {
		if err := s.Seeder.Sync(ctx); err != nil {
			return err
		}
	}
	if purgeEvery > 0 {
		go s.purgeLoop(ctx, purgeEvery)
	}
	return s.HTTP.Run(ctx)
}

// purgeLoop deletes sessions that ended more than a day ago. Safe to run on
// every replica (idempotent deletes); at scale, prefer the
// `maintenance purge-sessions` command on a schedule.
func (s *Server) purgeLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.Auth.PurgeSessions(ctx, time.Now().Add(-24*time.Hour))
			if err != nil && ctx.Err() == nil {
				s.Log.Warn("purge sessions failed", zap.Error(err))
			} else if n > 0 {
				s.Log.Info("purged ended sessions", zap.Int64("rows", n))
			}
		}
	}
}

// Tools is what the administrative CLI commands need.
type Tools struct {
	Seeder *service.Seeder
	Auth   *service.AuthService
}
