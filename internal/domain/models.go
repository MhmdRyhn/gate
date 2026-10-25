// Package domain holds the core entities and rules of the identity and
// access system. It depends on nothing but the standard library and uuid, so
// every other layer (services, storage, transport) can share it.
//
//	User ──< UserRole >── Role ──< RolePermission >── Permission   (internal users)
//	User ──< UserPublicType >── PublicUserType ──(optional)──> Role (public users)
//	User ──< UserIdentity                                           (SSO links)
//	User ──< Session ──< RefreshToken                               (sign-ins)
//
// Internal users (staff) hold any number of internal roles. Public users
// (customers of the application) hold one or more public types; a type may
// optionally carry a role, but public authorization is left to the business:
// most public endpoints only check the user's kind and type.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// UserStatus controls whether a user may authenticate at all.
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

// Valid reports whether s is a known status.
func (s UserStatus) Valid() bool {
	return s == UserStatusActive || s == UserStatusDisabled
}

// UserKind separates staff from users of the public application. It is
// fixed at creation. Roles carry the same value as their audience: a role can
// only be granted to users of that kind.
type UserKind string

const (
	UserKindInternal UserKind = "internal"
	UserKindPublic   UserKind = "public"
)

// Valid reports whether k is a known kind.
func (k UserKind) Valid() bool {
	return k == UserKindInternal || k == UserKindPublic
}

// User is an account. It signs in with an email or phone number (at least
// one is set) plus a password, and/or through linked SSO identities.
// Users are disabled rather than deleted so references stay intact.
type User struct {
	ID              uuid.UUID
	Email           *string // lower-cased
	Phone           *string // E.164, e.g. +8801712345678
	FullName        string
	PasswordHash    string // empty for SSO-only accounts
	Kind            UserKind
	Status          UserStatus
	PublicTypes     []string // public users only
	EmailVerifiedAt *time.Time
	PhoneVerifiedAt *time.Time
	LastLoginAt     *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// UserPatch is a partial update; nil fields are left unchanged.
type UserPatch struct {
	FullName *string
	Status   *UserStatus
}

// UserFilter narrows user listings; zero values match everything.
type UserFilter struct {
	Kind       *UserKind
	PublicType *string
	Limit      int
	Offset     int
}

// Role is a named bundle of permissions. System roles are defined in code
// (package rbac) and are read-only through the API.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	Audience    UserKind
	IsSystem    bool
	Permissions []Permission
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Permission identifies one operation, formatted "<resource>:<action>".
type Permission string

// PermissionDef describes a permission in the registry.
type PermissionDef struct {
	Code        Permission `json:"code"`
	Description string     `json:"description"`
}

// PublicUserType is a category of public user (e.g. customer, vendor).
// Types are defined in code; a user may hold several.
type PublicUserType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Role optionally names a public role whose permissions holders of this
	// type receive. Empty means the type grants no permissions.
	Role string `json:"role,omitempty"`
	// SelfRegistration allows public sign-up with this type. Other types
	// are granted by internal users only.
	SelfRegistration bool `json:"self_registration"`
}

// UserIdentity links a user to an account at an external identity provider
// (SSO). The pair (Provider, Subject) is globally unique.
type UserIdentity struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Provider   string // registry name, e.g. "google"
	Subject    string // provider's stable user ID ("sub" claim)
	Email      string // as asserted by the provider at link time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Session is one sign-in on one device. Access tokens reference it ("sid"),
// so revoking a session immediately invalidates its access tokens here.
type Session struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	AuthMethod      string // "password" or "sso:<provider>"
	IP              string
	UserAgent       string
	CreatedAt       time.Time
	LastRefreshedAt time.Time
	ExpiresAt       time.Time // absolute lifetime
	RevokedAt       *time.Time
}

// Active reports whether the session can still be used at time now.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// RefreshToken is a single-use credential belonging to a session. Only the
// SHA-256 hash of the token is stored. Using it rotates it (UsedAt is set and
// a successor is issued); presenting a used token again revokes the session.
type RefreshToken struct {
	ID        uuid.UUID
	SessionID uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// AuditEvent records a security-relevant action.
type AuditEvent struct {
	ID          uuid.UUID
	OccurredAt  time.Time
	ActorUserID *uuid.UUID
	Action      string // e.g. "auth.login.failed", "user.roles.changed"
	TargetType  string // e.g. "user", "role", "session"
	TargetID    string
	IP          string
	UserAgent   string
	RequestID   string
	Details     map[string]any
}

// AuditFilter narrows audit listings.
type AuditFilter struct {
	ActorUserID *uuid.UUID
	Action      string
	Limit       int
	Offset      int
}

// Principal is the authenticated actor of a request.
type Principal struct {
	UserID      uuid.UUID
	SessionID   uuid.UUID
	Kind        UserKind
	PublicTypes []string
	Permissions PermissionSet
}

// Can reports whether the principal holds perm.
func (p *Principal) Can(perm Permission) bool {
	return p != nil && p.Permissions.Has(perm)
}

// HasPublicType reports whether the principal holds any of the given types.
func (p *Principal) HasPublicType(types ...string) bool {
	if p == nil {
		return false
	}
	for _, have := range p.PublicTypes {
		for _, want := range types {
			if have == want {
				return true
			}
		}
	}
	return false
}
