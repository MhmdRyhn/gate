package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
	"github.com/MhmdRyhn/gate/internal/requestctx"
)

// Audit actions.
const (
	AuditLoginSucceeded    = "auth.login.succeeded"
	AuditLoginFailed       = "auth.login.failed"
	AuditRegistered        = "auth.registered"
	AuditSSOLogin          = "auth.sso.login"
	AuditSSOLinked         = "auth.sso.linked"
	AuditRefreshReuse      = "auth.refresh.reuse_detected"
	AuditLogout            = "auth.logout"
	AuditLogoutAll         = "auth.logout_all"
	AuditPasswordChanged   = "auth.password.changed"
	AuditUserCreated       = "user.created"
	AuditUserUpdated       = "user.updated"
	AuditUserRolesChanged  = "user.roles.changed"
	AuditUserTypesChanged  = "user.public_types.changed"
	AuditRoleCreated       = "role.created"
	AuditRoleUpdated       = "role.updated"
	AuditRoleDeleted       = "role.deleted"
	AuditAdminBootstrapped = "admin.bootstrapped"
)

// Auditor records security events. A failure to write an event is logged
// but never fails the user's request: availability of sign-in outweighs a
// missing audit row, and the log line still captures the event.
type Auditor struct {
	repo repository.AuditRepository
	log  *zap.Logger
}

// NewAuditor returns an Auditor.
func NewAuditor(repo repository.AuditRepository, log *zap.Logger) *Auditor {
	return &Auditor{repo: repo, log: log.Named("audit")}
}

// AuditEntry describes one event; request metadata is added automatically.
type AuditEntry struct {
	Actor      *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	Details    map[string]any
}

// Record stores the event, enriched with request ID, IP and user agent.
func (a *Auditor) Record(ctx context.Context, e AuditEntry) {
	meta := requestctx.From(ctx)
	ev := &domain.AuditEvent{
		ID: newID(), OccurredAt: time.Now().UTC(), ActorUserID: e.Actor, Action: e.Action,
		TargetType: e.TargetType, TargetID: e.TargetID, IP: meta.IP, UserAgent: truncate(meta.UserAgent, 512),
		RequestID: meta.RequestID, Details: e.Details,
	}
	// Detach from request cancellation: the event must be written even if
	// the client disconnects, but bounded in time.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := a.repo.Record(wctx, ev); err != nil {
		a.log.Error("failed to record audit event", zap.String("action", e.Action), zap.String("target_id", e.TargetID), zap.Error(err))
	}
}

// List returns audit events, newest first.
func (a *Auditor) List(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEvent, error) {
	return a.repo.List(ctx, f)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
