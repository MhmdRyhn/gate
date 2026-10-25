package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
)

var roleNameFormat = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,49}$`)

// RoleService manages internal roles. System roles (defined in code) are
// read-only here.
type RoleService struct {
	roles repository.RoleRepository
	audit *Auditor
}

// NewRoleService wires a RoleService.
func NewRoleService(roles repository.RoleRepository, audit *Auditor) *RoleService {
	return &RoleService{roles: roles, audit: audit}
}

// RoleInput creates a role; for updates nil fields are left unchanged.
type RoleInput struct {
	Name        *string
	Description *string
	Permissions *[]domain.Permission
}

// List returns every role.
func (s *RoleService) List(ctx context.Context) ([]domain.Role, error) { return s.roles.List(ctx) }

// Get returns one role.
func (s *RoleService) Get(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	return s.roles.GetByID(ctx, id)
}

// Create adds an internal role from permissions the actor holds.
func (s *RoleService) Create(ctx context.Context, actor *domain.Principal, in RoleInput) (*domain.Role, error) {
	r := &domain.Role{ID: newID(), Audience: domain.UserKindInternal}
	apply(r, in)
	if err := validateRole(r); err != nil {
		return nil, err
	}
	if err := ensureHolds(actor, r.Permissions); err != nil {
		return nil, err
	}
	if err := s.roles.Create(ctx, r); err != nil {
		return nil, roleConflict(err)
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditRoleCreated, TargetType: "role", TargetID: r.ID.String(),
		Details: map[string]any{"name": r.Name, "permissions": r.Permissions}})
	return s.roles.GetByID(ctx, r.ID)
}

// Update modifies a role the actor fully holds.
func (s *RoleService) Update(ctx context.Context, actor *domain.Principal, id uuid.UUID, in RoleInput) (*domain.Role, error) {
	r, err := s.editable(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	before := r.Permissions
	apply(r, in)
	if err := validateRole(r); err != nil {
		return nil, err
	}
	if err := ensureHolds(actor, r.Permissions); err != nil {
		return nil, err
	}
	if err := s.roles.Update(ctx, r); err != nil {
		return nil, roleConflict(err)
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditRoleUpdated, TargetType: "role", TargetID: id.String(),
		Details: map[string]any{"permissions_before": before, "permissions_after": r.Permissions}})
	return s.roles.GetByID(ctx, id)
}

// Delete removes a role that is no longer assigned.
func (s *RoleService) Delete(ctx context.Context, actor *domain.Principal, id uuid.UUID) error {
	r, err := s.editable(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := s.roles.Delete(ctx, id); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return fmt.Errorf("%w: role is still assigned to users", domain.ErrConflict)
		}
		return err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditRoleDeleted, TargetType: "role", TargetID: id.String(),
		Details: map[string]any{"name": r.Name}})
	return nil
}

// editable loads a non-system role whose permissions the actor holds.
func (s *RoleService) editable(ctx context.Context, actor *domain.Principal, id uuid.UUID) (*domain.Role, error) {
	r, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.IsSystem {
		return nil, fmt.Errorf("%w: system roles are managed in code", domain.ErrForbidden)
	}
	return r, ensureHolds(actor, r.Permissions)
}

func apply(r *domain.Role, in RoleInput) {
	if in.Name != nil {
		r.Name = *in.Name
	}
	if in.Description != nil {
		r.Description = *in.Description
	}
	if in.Permissions != nil {
		r.Permissions = *in.Permissions
	}
}

func validateRole(r *domain.Role) error {
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	if !roleNameFormat.MatchString(r.Name) {
		return domain.Invalid("name must be 2-50 chars of a-z, 0-9, '_' or '-', starting with a letter")
	}
	if len([]rune(r.Description)) > 500 {
		return domain.Invalid("description must be at most 500 characters")
	}
	perms, err := cleanPermissions(r.Permissions)
	if err != nil {
		return err
	}
	r.Permissions = perms
	return nil
}

func roleConflict(err error) error {
	if errors.Is(err, domain.ErrConflict) {
		return fmt.Errorf("%w: role name already exists", domain.ErrConflict)
	}
	return err
}
