// Package repository defines the persistence ports. Services depend only on
// these interfaces; package postgres implements them with gorm. Every
// method returns domain.ErrNotFound / domain.ErrConflict where relevant.
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
)

// CreateUserOptions are written atomically with a new user.
type CreateUserOptions struct {
	RoleIDs     []uuid.UUID          // internal users
	PublicTypes []string             // public users
	Identity    *domain.UserIdentity // SSO sign-up
}

// UserRepository stores users and their access assignments.
type UserRepository interface {
	Create(ctx context.Context, u *domain.User, opts CreateUserOptions) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	List(ctx context.Context, f domain.UserFilter) ([]domain.User, error)
	Count(ctx context.Context) (int64, error)
	Update(ctx context.Context, id uuid.UUID, patch domain.UserPatch) (*domain.User, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, hash string) error
	TouchLastLogin(ctx context.Context, id uuid.UUID) error

	// SetRoles replaces an internal user's roles.
	SetRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	// SetPublicTypes replaces a public user's types.
	SetPublicTypes(ctx context.Context, userID uuid.UUID, types []string) error
	// EffectiveRoles returns the user's assigned roles plus roles granted
	// by their public types.
	EffectiveRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error)
	// GetPrincipal loads an active user and session with effective
	// permissions. ErrNotFound if the session is unknown, revoked or
	// expired; ErrUserDisabled if the user is disabled.
	GetPrincipal(ctx context.Context, userID, sessionID uuid.UUID) (*domain.Principal, error)
}

// RoleRepository stores roles, permissions and public user types.
type RoleRepository interface {
	Create(ctx context.Context, r *domain.Role) error
	Update(ctx context.Context, r *domain.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	GetByName(ctx context.Context, name string) (*domain.Role, error)
	GetByIDs(ctx context.Context, ids []uuid.UUID) ([]domain.Role, error)
	List(ctx context.Context) ([]domain.Role, error)

	// SyncPermissions makes the permissions table equal defs.
	SyncPermissions(ctx context.Context, defs []domain.PermissionDef) error
	// SeedRole creates r if missing; when overwrite is set, an existing
	// role's description and permissions are replaced.
	SeedRole(ctx context.Context, r *domain.Role, overwrite bool) error
	// SyncPublicUserTypes makes public_user_types equal defs. Removing a
	// type still held by users fails.
	SyncPublicUserTypes(ctx context.Context, defs []domain.PublicUserType) error
}

// SessionRepository stores sessions and their refresh tokens.
type SessionRepository interface {
	// Create stores a new session with its first refresh token.
	Create(ctx context.Context, s *domain.Session, rt *domain.RefreshToken) error
	// GetByRefreshToken finds a refresh token by hash with its session.
	GetByRefreshToken(ctx context.Context, hash []byte) (*domain.RefreshToken, *domain.Session, error)
	// Rotate marks oldTokenID used and stores next, atomically. It returns
	// domain.ErrInvalidToken if oldTokenID was already used.
	Rotate(ctx context.Context, oldTokenID uuid.UUID, next *domain.RefreshToken) error
	Revoke(ctx context.Context, sessionID uuid.UUID) error
	// RevokeAllForUser revokes every session of the user except keep (if set).
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, keep *uuid.UUID) error
	// Purge deletes sessions and refresh tokens that expired or were revoked before t.
	Purge(ctx context.Context, before time.Time) (int64, error)
}

// IdentityRepository stores SSO identity links.
type IdentityRepository interface {
	// FindUser returns the user linked to (provider, subject) and records the use.
	FindUser(ctx context.Context, provider, subject string) (*domain.User, error)
	Link(ctx context.Context, id *domain.UserIdentity) error
}

// AuditRepository stores the append-only audit log.
type AuditRepository interface {
	Record(ctx context.Context, e *domain.AuditEvent) error
	List(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEvent, error)
}

// HealthChecker reports whether the database is reachable.
type HealthChecker interface {
	Ping(ctx context.Context) error
}
