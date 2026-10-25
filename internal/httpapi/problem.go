// Package httpapi is the HTTP transport (gin): routing, middleware,
// request validation and mapping between DTOs and services.
package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/requestctx"
)

// Problem is an RFC 9457 "problem details" error body, served as
// application/problem+json. Code is a stable, machine-readable extension.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}

func writeProblem(c *gin.Context, status int, code, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, Problem{
		Type: "about:blank", Title: http.StatusText(status), Status: status,
		Detail: detail, Code: code, RequestID: requestctx.From(c.Request.Context()).RequestID,
	})
}

// errorWriter maps errors to problem responses. Unexpected errors are
// logged with the request ID and hidden from the client.
type errorWriter struct{ log *zap.Logger }

func (e errorWriter) write(c *gin.Context, err error) {
	var ve *domain.ValidationError
	var fe validator.ValidationErrors
	switch {
	case errors.As(err, &ve):
		writeProblem(c, http.StatusBadRequest, "invalid_request", ve.Message)
	case errors.As(err, &fe):
		writeProblem(c, http.StatusBadRequest, "invalid_request", describeValidation(fe))
	case errors.Is(err, errBadJSON):
		writeProblem(c, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, domain.ErrNotFound):
		writeProblem(c, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, domain.ErrConflict):
		writeProblem(c, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, domain.ErrUnauthenticated):
		c.Header("WWW-Authenticate", `Bearer realm="rbac-service"`)
		writeProblem(c, http.StatusUnauthorized, "unauthenticated", "authentication required")
	case errors.Is(err, domain.ErrInvalidToken):
		c.Header("WWW-Authenticate", `Bearer realm="rbac-service", error="invalid_token"`)
		writeProblem(c, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
	case errors.Is(err, domain.ErrInvalidCredentials):
		writeProblem(c, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, domain.ErrUserDisabled):
		writeProblem(c, http.StatusForbidden, "account_disabled", "account is disabled")
	case errors.Is(err, domain.ErrForbidden):
		writeProblem(c, http.StatusForbidden, "forbidden", err.Error())
	default:
		e.log.Error("internal error",
			zap.String("request_id", requestctx.From(c.Request.Context()).RequestID),
			zap.String("route", c.FullPath()), zap.Error(err))
		writeProblem(c, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

var errBadJSON = errors.New("invalid JSON body")

// bindJSON decodes and validates a JSON body (unknown fields are rejected,
// see NewRouter).
func bindJSON(c *gin.Context, dst any) error {
	if err := c.ShouldBindJSON(dst); err != nil {
		var fe validator.ValidationErrors
		if errors.As(err, &fe) {
			return fe
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fmt.Errorf("%w: body too large", errBadJSON)
		}
		return fmt.Errorf("%w: %s", errBadJSON, err.Error())
	}
	return nil
}

func describeValidation(errs validator.ValidationErrors) string {
	msgs := make([]string, 0, len(errs))
	for _, fe := range errs {
		field := fe.Field()
		switch fe.Tag() {
		case "required":
			msgs = append(msgs, field+" is required")
		case "max":
			msgs = append(msgs, fmt.Sprintf("%s must be at most %s", field, fe.Param()))
		case "oneof":
			msgs = append(msgs, fmt.Sprintf("%s must be one of: %s", field, fe.Param()))
		default:
			msgs = append(msgs, fmt.Sprintf("%s failed %q validation", field, fe.Tag()))
		}
	}
	return strings.Join(msgs, "; ")
}
