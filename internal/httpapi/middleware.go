package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/requestctx"
)

const principalKey = "principal"

// Authenticator verifies a bearer token and returns the principal.
// Implemented by service.AuthService.
type Authenticator interface {
	Authenticate(ctx context.Context, rawToken string) (*domain.Principal, error)
}

// principalFrom returns the principal set by authenticate.
func principalFrom(c *gin.Context) *domain.Principal {
	p, _ := c.Get(principalKey)
	pr, _ := p.(*domain.Principal)
	return pr
}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// requestMeta assigns a request ID (reusing a well-formed incoming
// X-Request-ID for cross-service tracing) and stores request metadata in
// the context for services, audit and logs.
func requestMeta() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if !validRequestID.MatchString(id) {
			id = uuid.NewString()
		}
		c.Header("X-Request-ID", id)
		ctx := requestctx.With(c.Request.Context(), requestctx.Meta{RequestID: id, IP: c.ClientIP(), UserAgent: c.Request.UserAgent()})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// accessLog logs one line per request. It logs the route template, not the
// raw path or query string, so tokens, codes or PII in URLs never reach logs.
func accessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		meta := requestctx.From(c.Request.Context())
		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("route", c.FullPath()),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("ip", meta.IP),
			zap.String("request_id", meta.RequestID),
		}
		if p := principalFrom(c); p != nil {
			fields = append(fields, zap.String("user_id", p.UserID.String()))
		}
		if c.Writer.Status() >= 500 {
			log.Warn("http request", fields...)
		} else {
			log.Info("http request", fields...)
		}
	}
}

// recovery turns panics into 500 responses and logs the stack trace.
func recovery(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic", zap.Any("panic", v), zap.ByteString("stack", debug.Stack()),
					zap.String("request_id", requestctx.From(c.Request.Context()).RequestID))
				writeProblem(c, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		c.Next()
	}
}

// securityHeaders hardens responses. This is a JSON API: nothing may be
// framed, sniffed or cached (RFC 6749 §5.1 requires no-store for tokens).
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		c.Next()
	}
}

// bodyLimit caps request bodies.
func bodyLimit(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

// authenticate requires a valid bearer access token and stores the principal.
func authenticate(a Authenticator, ew errorWriter) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, token, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
			ew.write(c, domain.ErrUnauthenticated)
			return
		}
		p, err := a.Authenticate(c.Request.Context(), token)
		if err != nil {
			ew.write(c, err)
			return
		}
		c.Set(principalKey, p)
		c.Next()
	}
}

// RequireKind allows only users of the given kind (internal or public).
func RequireKind(kind domain.UserKind) gin.HandlerFunc {
	return func(c *gin.Context) {
		if p := principalFrom(c); p == nil || p.Kind != kind {
			writeProblem(c, http.StatusForbidden, "forbidden", fmt.Sprintf("only %s users may call this endpoint", kind))
			return
		}
		c.Next()
	}
}

// RequirePermissions allows only principals holding every listed permission.
func RequirePermissions(perms ...domain.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := principalFrom(c)
		for _, perm := range perms {
			if !p.Can(perm) {
				writeProblem(c, http.StatusForbidden, "forbidden", fmt.Sprintf("requires permission %q", perm))
				return
			}
		}
		c.Next()
	}
}

// RequirePublicType allows only public users holding at least one of types.
// Use it for public endpoints that differ per type (e.g. vendor-only).
func RequirePublicType(types ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !principalFrom(c).HasPublicType(types...) {
			writeProblem(c, http.StatusForbidden, "forbidden", fmt.Sprintf("requires public type: %s", strings.Join(types, " or ")))
			return
		}
		c.Next()
	}
}

// rateLimit applies a per-client-IP token bucket.
func rateLimit(l *ipLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.allow(c.ClientIP()) {
			c.Header("Retry-After", fmt.Sprint(int(l.retryAfter().Seconds())+1))
			writeProblem(c, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		c.Next()
	}
}
