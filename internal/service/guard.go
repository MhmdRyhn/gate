// Package service implements the use cases (sign-in, registration, SSO,
// user and role management) on top of the repository interfaces. All
// authorization decisions that depend on data (privilege escalation, kind
// separation) live here; the HTTP layer only checks route-level access.
package service

import (
	"context"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// Limits on collection inputs, to bound work per request.
const (
	maxRolesPerUser       = 50
	maxPublicTypesPerUser = 10
)

// ensureHolds is the privilege-escalation guard: an actor may only grant,
// revoke or edit permissions they hold themselves. A manager therefore
// cannot create an admin, edit an admin's roles or disable an admin.
func ensureHolds(actor *domain.Principal, perms []domain.Permission) error {
	for _, p := range perms {
		if !actor.Can(p) {
			return fmt.Errorf("%w: requires permission %q", domain.ErrForbidden, p)
		}
	}
	return nil
}

func rolePermissions(roles []domain.Role) []domain.Permission {
	var out []domain.Permission
	for _, r := range roles {
		out = append(out, r.Permissions...)
	}
	return out
}

// ensureCanGrantRoles checks that every role exists, is internal, and that
// the actor holds all of its permissions. It returns de-duplicated IDs.
func ensureCanGrantRoles(ctx context.Context, roles repository.RoleRepository, actor *domain.Principal, ids []uuid.UUID) ([]uuid.UUID, error) {
	ids = dedupe(ids)
	if len(ids) > maxRolesPerUser {
		return nil, domain.Invalid("at most %d roles per user", maxRolesPerUser)
	}
	found, err := roles.GetByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	if len(found) != len(ids) {
		return nil, domain.Invalid("one or more roles do not exist")
	}
	for _, r := range found {
		if r.Audience != domain.UserKindInternal {
			return nil, domain.Invalid("role %q is a public role and is granted through public types", r.Name)
		}
	}
	return ids, ensureHolds(actor, rolePermissions(found))
}

// ensureCanGrantPublicTypes checks that every type exists and, for types
// that carry a role, that the actor holds the role's permissions.
func ensureCanGrantPublicTypes(ctx context.Context, roles repository.RoleRepository, actor *domain.Principal, types []string) ([]string, error) {
	types = dedupe(types)
	if len(types) == 0 {
		return nil, domain.Invalid("public users need at least one public type")
	}
	if len(types) > maxPublicTypesPerUser {
		return nil, domain.Invalid("at most %d public types per user", maxPublicTypesPerUser)
	}
	for _, name := range types {
		t, ok := rbac.LookupPublicType(name)
		if !ok {
			return nil, domain.Invalid("unknown public type %q", name)
		}
		if t.Role == "" {
			continue
		}
		role, err := roles.GetByName(ctx, t.Role)
		if err != nil {
			return nil, err
		}
		if err := ensureHolds(actor, role.Permissions); err != nil {
			return nil, err
		}
	}
	slices.Sort(types)
	return types, nil
}

// ensureCanManageUser loads the target and checks that the actor holds every
// permission the target holds.
func ensureCanManageUser(ctx context.Context, users repository.UserRepository, actor *domain.Principal, id uuid.UUID) (*domain.User, error) {
	u, err := users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	roles, err := users.EffectiveRoles(ctx, id)
	if err != nil {
		return nil, err
	}
	return u, ensureHolds(actor, rolePermissions(roles))
}

// cleanPermissions validates, de-duplicates and sorts permission codes.
func cleanPermissions(perms []domain.Permission) ([]domain.Permission, error) {
	out := slices.Clone(perms)
	slices.Sort(out)
	out = slices.Compact(out)
	for _, p := range out {
		if !rbac.IsKnown(p) {
			return nil, domain.Invalid("unknown permission %q", p)
		}
	}
	return out, nil
}

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || len(s) > 254 {
		return "", domain.Invalid("invalid email address")
	}
	return s, nil
}

var (
	phoneSeparators = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", ".", "")
	e164            = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
)

// normalizePhone accepts international numbers with common separators
// ("+880 1712-345678", "00880...") and returns E.164 ("+8801712345678").
func normalizePhone(s string) (string, error) {
	s = phoneSeparators.Replace(strings.TrimSpace(s))
	if strings.HasPrefix(s, "00") {
		s = "+" + s[2:]
	}
	if !e164.MatchString(s) {
		return "", domain.Invalid("phone must be in international format, e.g. +8801712345678")
	}
	return s, nil
}

// contactInput validates an optional email and phone (at least one is
// required) and returns them normalised.
func contactInput(email, phone string) (*string, *string, error) {
	var e, p *string
	if strings.TrimSpace(email) != "" {
		v, err := normalizeEmail(email)
		if err != nil {
			return nil, nil, err
		}
		e = &v
	}
	if strings.TrimSpace(phone) != "" {
		v, err := normalizePhone(phone)
		if err != nil {
			return nil, nil, err
		}
		p = &v
	}
	if e == nil && p == nil {
		return nil, nil, domain.Invalid("email or phone is required")
	}
	return e, p, nil
}

func cleanFullName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 200 {
		return "", domain.Invalid("full_name must be at most 200 characters")
	}
	return s, nil
}

func dedupe[T comparable](in []T) []T {
	seen := make(map[T]bool, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// newID returns a time-ordered UUIDv7, which keeps B-tree inserts local.
func newID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New()
	}
	return id
}
