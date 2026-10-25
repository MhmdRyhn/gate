package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// Seeder writes the code-defined registry (permissions, default roles,
// public user types) into the database and bootstraps the first admin.
// All operations are idempotent and safe to run concurrently.
type Seeder struct {
	users repository.UserRepository
	roles repository.RoleRepository
	auth  *AuthService
	audit *Auditor
	log   *zap.Logger
}

// NewSeeder wires a Seeder.
func NewSeeder(users repository.UserRepository, roles repository.RoleRepository, auth *AuthService, audit *Auditor, log *zap.Logger) *Seeder {
	return &Seeder{users: users, roles: roles, auth: auth, audit: audit, log: log}
}

// Sync makes the database match package rbac.
func (s *Seeder) Sync(ctx context.Context) error {
	if err := s.roles.SyncPermissions(ctx, rbac.Permissions); err != nil {
		return fmt.Errorf("sync permissions: %w", err)
	}
	for _, t := range rbac.DefaultRoles {
		r := &domain.Role{ID: newID(), Name: t.Name, Description: t.Description, Audience: t.Audience, IsSystem: t.System, Permissions: t.Permissions}
		if err := s.roles.SeedRole(ctx, r, t.System); err != nil {
			return fmt.Errorf("seed role %s: %w", t.Name, err)
		}
	}
	if err := s.roles.SyncPublicUserTypes(ctx, rbac.PublicUserTypes); err != nil {
		return fmt.Errorf("sync public user types: %w", err)
	}
	s.log.Info("rbac registry synced",
		zap.Int("permissions", len(rbac.Permissions)), zap.Int("roles", len(rbac.DefaultRoles)), zap.Int("public_types", len(rbac.PublicUserTypes)))
	return nil
}

// CreateAdmin creates an internal user holding the admin role. Used by the
// `admin create` command for the first account (and break-glass recovery).
func (s *Seeder) CreateAdmin(ctx context.Context, email, phone, fullName, password string) (*domain.User, error) {
	admin, err := s.roles.GetByName(ctx, rbac.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("admin role not found (run `seed` first): %w", err)
	}
	u, err := s.auth.newUser(email, phone, fullName, password, domain.UserKindInternal)
	if err != nil {
		return nil, err
	}
	if err := createUser(ctx, s.users, u, repository.CreateUserOptions{RoleIDs: []uuid.UUID{admin.ID}}); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Action: AuditAdminBootstrapped, TargetType: "user", TargetID: u.ID.String()})
	return u, nil
}
