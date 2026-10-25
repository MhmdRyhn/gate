package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// UserService manages users on behalf of internal staff.
type UserService struct {
	users repository.UserRepository
	roles repository.RoleRepository
	auth  *AuthService
	audit *Auditor
}

// NewUserService wires a UserService.
func NewUserService(users repository.UserRepository, roles repository.RoleRepository, auth *AuthService, audit *Auditor) *UserService {
	return &UserService{users: users, roles: roles, auth: auth, audit: audit}
}

// UserDetails is a user with its effective roles.
type UserDetails struct {
	User  *domain.User
	Roles []domain.Role
}

// CreateUserInput creates a user of either kind.
type CreateUserInput struct {
	Email, Phone, FullName, Password string
	Kind                             domain.UserKind // default internal
	RoleIDs                          []uuid.UUID     // internal users only
	PublicTypes                      []string        // public users only, at least one
}

// Create adds a user. Granting roles requires users:assign_roles, and the
// actor must hold every permission the new user would receive.
func (s *UserService) Create(ctx context.Context, actor *domain.Principal, in CreateUserInput) (*UserDetails, error) {
	if in.Kind == "" {
		in.Kind = domain.UserKindInternal
	}
	if !in.Kind.Valid() {
		return nil, domain.Invalid("kind must be %q or %q", domain.UserKindInternal, domain.UserKindPublic)
	}
	var opts repository.CreateUserOptions
	var err error
	switch in.Kind {
	case domain.UserKindInternal:
		if len(in.PublicTypes) > 0 {
			return nil, domain.Invalid("public_types are only allowed for public users")
		}
		if len(in.RoleIDs) > 0 {
			if !actor.Can(rbac.UsersAssignRoles) {
				return nil, fmt.Errorf("%w: requires permission %q", domain.ErrForbidden, rbac.UsersAssignRoles)
			}
			if opts.RoleIDs, err = ensureCanGrantRoles(ctx, s.roles, actor, in.RoleIDs); err != nil {
				return nil, err
			}
		}
	case domain.UserKindPublic:
		if len(in.RoleIDs) > 0 {
			return nil, domain.Invalid("public users get access through public_types; role_ids are not allowed")
		}
		if opts.PublicTypes, err = ensureCanGrantPublicTypes(ctx, s.roles, actor, in.PublicTypes); err != nil {
			return nil, err
		}
	}

	u, err := s.auth.newUser(in.Email, in.Phone, in.FullName, in.Password, in.Kind)
	if err != nil {
		return nil, err
	}
	if err := createUser(ctx, s.users, u, opts); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditUserCreated, TargetType: "user", TargetID: u.ID.String(),
		Details: map[string]any{"kind": u.Kind, "role_ids": opts.RoleIDs, "public_types": opts.PublicTypes}})
	return s.Get(ctx, u.ID)
}

// Get returns a user with effective roles.
func (s *UserService) Get(ctx context.Context, id uuid.UUID) (*UserDetails, error) {
	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	roles, err := s.users.EffectiveRoles(ctx, id)
	if err != nil {
		return nil, err
	}
	return &UserDetails{User: u, Roles: roles}, nil
}

// List returns users matching f.
func (s *UserService) List(ctx context.Context, f domain.UserFilter) ([]domain.User, error) {
	if f.Kind != nil && !f.Kind.Valid() {
		return nil, domain.Invalid("kind must be %q or %q", domain.UserKindInternal, domain.UserKindPublic)
	}
	return s.users.List(ctx, f)
}

// Update changes profile fields or status. Disabling a user revokes all of
// their sessions immediately.
func (s *UserService) Update(ctx context.Context, actor *domain.Principal, id uuid.UUID, patch domain.UserPatch) (*UserDetails, error) {
	if patch.FullName != nil {
		name, err := cleanFullName(*patch.FullName)
		if err != nil {
			return nil, err
		}
		patch.FullName = &name
	}
	if patch.Status != nil {
		if !patch.Status.Valid() {
			return nil, domain.Invalid("status must be %q or %q", domain.UserStatusActive, domain.UserStatusDisabled)
		}
		if id == actor.UserID {
			return nil, domain.Invalid("you cannot change your own status")
		}
	}
	if _, err := ensureCanManageUser(ctx, s.users, actor, id); err != nil {
		return nil, err
	}
	if _, err := s.users.Update(ctx, id, patch); err != nil {
		return nil, err
	}
	if patch.Status != nil && *patch.Status == domain.UserStatusDisabled {
		if err := s.auth.sessions.RevokeAllForUser(ctx, id, nil); err != nil {
			return nil, err
		}
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditUserUpdated, TargetType: "user", TargetID: id.String(),
		Details: map[string]any{"full_name_changed": patch.FullName != nil, "status": patch.Status}})
	return s.Get(ctx, id)
}

// SetRoles replaces an internal user's roles. The actor must be able to
// manage both the roles removed and the roles granted.
func (s *UserService) SetRoles(ctx context.Context, actor *domain.Principal, id uuid.UUID, roleIDs []uuid.UUID) (*UserDetails, error) {
	if id == actor.UserID {
		return nil, domain.Invalid("you cannot change your own roles")
	}
	u, err := ensureCanManageUser(ctx, s.users, actor, id)
	if err != nil {
		return nil, err
	}
	if u.Kind != domain.UserKindInternal {
		return nil, domain.Invalid("public users get access through public types; use the public-types endpoint")
	}
	if roleIDs, err = ensureCanGrantRoles(ctx, s.roles, actor, roleIDs); err != nil {
		return nil, err
	}
	if err := s.users.SetRoles(ctx, id, roleIDs); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditUserRolesChanged, TargetType: "user", TargetID: id.String(),
		Details: map[string]any{"role_ids": roleIDs}})
	return s.Get(ctx, id)
}

// SetPublicTypes replaces a public user's types (one or more).
func (s *UserService) SetPublicTypes(ctx context.Context, actor *domain.Principal, id uuid.UUID, types []string) (*UserDetails, error) {
	u, err := ensureCanManageUser(ctx, s.users, actor, id)
	if err != nil {
		return nil, err
	}
	if u.Kind != domain.UserKindPublic {
		return nil, domain.Invalid("public types can only be set on public users")
	}
	if types, err = ensureCanGrantPublicTypes(ctx, s.roles, actor, types); err != nil {
		return nil, err
	}
	if err := s.users.SetPublicTypes(ctx, id, types); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &actor.UserID, Action: AuditUserTypesChanged, TargetType: "user", TargetID: id.String(),
		Details: map[string]any{"from": u.PublicTypes, "to": types}})
	return s.Get(ctx, id)
}
