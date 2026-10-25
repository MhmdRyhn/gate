// Package config defines the application's typed configuration and loads it
// from one or more pluggable Sources (environment, files, Kubernetes
// ConfigMap/Secret volumes, Consul, AWS AppConfig, ...).
//
// Every setting is identified by a single flat key (e.g. "DATABASE_URL"),
// whatever the source. That keeps sources interchangeable: the same key can
// come from an env var in development and from a Kubernetes Secret in
// production without code changes.
package config

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/sethvargo/go-envconfig"
)

// Config is the complete application configuration.
type Config struct {
	App      AppConfig
	HTTP     HTTPConfig
	Database DatabaseConfig
	Log      LogConfig
	Auth     AuthConfig
	JWT      JWTConfig
}

// AppConfig holds general application settings.
type AppConfig struct {
	// Env is "production" or "development". Development relaxes nothing
	// security-related; it only switches log format and gin debug output.
	Env string `env:"APP_ENV, default=production"`
}

// HTTPConfig configures the HTTP server.
type HTTPConfig struct {
	Addr              string        `env:"HTTP_ADDR, default=:8080"`
	ReadHeaderTimeout time.Duration `env:"HTTP_READ_HEADER_TIMEOUT, default=5s"`
	ReadTimeout       time.Duration `env:"HTTP_READ_TIMEOUT, default=15s"`
	WriteTimeout      time.Duration `env:"HTTP_WRITE_TIMEOUT, default=15s"`
	IdleTimeout       time.Duration `env:"HTTP_IDLE_TIMEOUT, default=60s"`
	ShutdownTimeout   time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT, default=20s"`
	MaxBodyBytes      int64         `env:"HTTP_MAX_BODY_BYTES, default=1048576"`
	// TrustedProxies lists proxy IPs/CIDRs whose X-Forwarded-For header is
	// trusted to determine the client IP. Empty means trust none.
	TrustedProxies []string `env:"HTTP_TRUSTED_PROXIES"`
	// CORSAllowedOrigins enables CORS for browser clients of the listed
	// origins (e.g. "https://app.example.com"). Empty disables CORS.
	CORSAllowedOrigins []string `env:"HTTP_CORS_ALLOWED_ORIGINS"`
}

// DatabaseConfig configures the PostgreSQL connection pool.
type DatabaseConfig struct {
	URL             Secret        `env:"DATABASE_URL, required"`
	MaxOpenConns    int           `env:"DB_MAX_OPEN_CONNS, default=25"`
	MaxIdleConns    int           `env:"DB_MAX_IDLE_CONNS, default=5"`
	ConnMaxLifetime time.Duration `env:"DB_CONN_MAX_LIFETIME, default=30m"`
	ConnMaxIdleTime time.Duration `env:"DB_CONN_MAX_IDLE_TIME, default=5m"`
	// ConnectTimeout bounds how long startup keeps retrying an unreachable
	// database before giving up.
	ConnectTimeout time.Duration `env:"DB_CONNECT_TIMEOUT, default=60s"`
	// SlowQueryThreshold logs queries slower than this at warn level.
	SlowQueryThreshold time.Duration `env:"DB_SLOW_QUERY_THRESHOLD, default=200ms"`
}

// LogConfig configures zap.
type LogConfig struct {
	Level  string `env:"LOG_LEVEL, default=info"`  // debug|info|warn|error
	Format string `env:"LOG_FORMAT, default=json"` // json|console
}

// AuthConfig configures sessions, registration and abuse protection.
type AuthConfig struct {
	// AccessTokenTTL is the lifetime of a JWT access token.
	AccessTokenTTL time.Duration `env:"ACCESS_TOKEN_TTL, default=15m"`
	// RefreshTokenTTL is the idle timeout of a session: a refresh token
	// unused for this long expires.
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL, default=168h"`
	// SessionMaxLifetime is the absolute session lifetime; after it the
	// user must sign in again regardless of activity.
	SessionMaxLifetime time.Duration `env:"SESSION_MAX_LIFETIME, default=720h"`

	PublicRegistrationEnabled bool `env:"PUBLIC_REGISTRATION_ENABLED, default=true"`

	// Per-client-IP token bucket for login, register and refresh.
	RateLimitPerMinute int `env:"AUTH_RATE_LIMIT_PER_MINUTE, default=10"`
	RateLimitBurst     int `env:"AUTH_RATE_LIMIT_BURST, default=10"`

	// SSOStateKey signs the short-lived SSO state cookie. Required (>= 32
	// bytes) only when at least one SSO provider is registered.
	SSOStateKey Secret `env:"SSO_STATE_KEY"`
}

// JWTConfig configures access token signing. See docs/jwt.md.
type JWTConfig struct {
	// Issuer ("iss") should be the public base URL of this service.
	Issuer string `env:"JWT_ISSUER, required"`
	// Audience ("aud") identifies the APIs that accept the token.
	Audience string `env:"JWT_AUDIENCE, default=rbac-service"`
	// SigningKey is a PKCS#8 PEM (or base64 of it) Ed25519 or RSA private key.
	SigningKey Secret `env:"JWT_SIGNING_KEY, required"`
	// VerificationKeys are extra PEM public keys still accepted for
	// verification, used during key rotation.
	VerificationKeys Secret `env:"JWT_VERIFICATION_KEYS"`
}

// Load reads all sources (later sources override earlier ones), decodes them
// into Config and validates the result.
func Load(ctx context.Context, sources ...Source) (*Config, error) {
	var c Config
	if err := Decode(ctx, &c, sources...); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Decode merges the key/value pairs of every source and decodes them into
// target, a pointer to any struct using `env:"KEY, default=..., required"`
// tags. It is independent of Config so other components can reuse it.
func Decode(ctx context.Context, target any, sources ...Source) error {
	merged := map[string]string{}
	for _, s := range sources {
		kv, err := s.Load(ctx)
		if err != nil {
			return fmt.Errorf("config source %s: %w", s.Name(), err)
		}
		for k, v := range kv {
			merged[k] = v
		}
	}
	return envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:   target,
		Lookuper: envconfig.MapLookuper(merged),
	})
}

// Validate checks cross-field rules that struct tags cannot express.
func (c *Config) Validate() error {
	var errs []error
	if !slices.Contains([]string{"production", "development"}, c.App.Env) {
		errs = append(errs, errors.New("APP_ENV must be production or development"))
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level) {
		errs = append(errs, errors.New("LOG_LEVEL must be debug, info, warn or error"))
	}
	if !slices.Contains([]string{"json", "console"}, c.Log.Format) {
		errs = append(errs, errors.New("LOG_FORMAT must be json or console"))
	}
	for name, d := range map[string]time.Duration{
		"ACCESS_TOKEN_TTL":     c.Auth.AccessTokenTTL,
		"REFRESH_TOKEN_TTL":    c.Auth.RefreshTokenTTL,
		"SESSION_MAX_LIFETIME": c.Auth.SessionMaxLifetime,
	} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	if c.Auth.AccessTokenTTL > time.Hour {
		errs = append(errs, errors.New("ACCESS_TOKEN_TTL must be at most 1h: access tokens cannot be revoked by other services"))
	}
	if c.Auth.RefreshTokenTTL > c.Auth.SessionMaxLifetime {
		errs = append(errs, errors.New("REFRESH_TOKEN_TTL must not exceed SESSION_MAX_LIFETIME"))
	}
	if c.Auth.RateLimitPerMinute <= 0 || c.Auth.RateLimitBurst <= 0 {
		errs = append(errs, errors.New("AUTH_RATE_LIMIT_PER_MINUTE and AUTH_RATE_LIMIT_BURST must be positive"))
	}
	if c.Database.MaxOpenConns <= 0 || c.Database.MaxIdleConns < 0 || c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		errs = append(errs, errors.New("DB_MAX_OPEN_CONNS must be positive and >= DB_MAX_IDLE_CONNS"))
	}
	if c.HTTP.MaxBodyBytes <= 0 {
		errs = append(errs, errors.New("HTTP_MAX_BODY_BYTES must be positive"))
	}
	return errors.Join(errs...)
}
