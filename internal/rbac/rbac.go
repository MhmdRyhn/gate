// Package rbac is the single source of truth for the operations the system
// knows about (permissions), the roles it ships with, and the types of public
// user. The `seed` command (also run by `serve --sync-rbac`) writes this
// registry into the database.
//
// Adding an internal operation:
//  1. Declare a Permission constant and add it to Permissions.
//  2. Protect the route with middleware.RequirePermissions(...).
//
// Public users: authorization of the public application is a business
// decision. Most public routes only need RequireKind(public) and, if they
// differ per type, RequirePublicType(...). If a type does need fine-grained
// permissions, add a public role to DefaultRoles and reference it from the
// type's Role field.
package rbac

import "github.com/MhmdRyhn/gate/internal/domain"

// Internal (staff) operations.
const (
	UsersRead        domain.Permission = "users:read"
	UsersCreate      domain.Permission = "users:create"
	UsersUpdate      domain.Permission = "users:update"
	UsersAssignRoles domain.Permission = "users:assign_roles"
	RolesRead        domain.Permission = "roles:read"
	RolesManage      domain.Permission = "roles:manage"
	AuditRead        domain.Permission = "audit:read"
)

// Permissions is the registry of every permission the application enforces.
var Permissions = []domain.PermissionDef{
	{Code: UsersRead, Description: "View users, their roles and public types"},
	{Code: UsersCreate, Description: "Create users"},
	{Code: UsersUpdate, Description: "Update user profile, status and public types"},
	{Code: UsersAssignRoles, Description: "Assign roles to internal users"},
	{Code: RolesRead, Description: "View roles, permissions and public types"},
	{Code: RolesManage, Description: "Create, update and delete internal roles"},
	{Code: AuditRead, Description: "Read the security audit log"},
}

// Internal roles.
const (
	RoleAdmin   = "admin"
	RoleManager = "manager"
	RoleViewer  = "viewer"
	RoleAuditor = "auditor"
)

// RoleTemplate describes a role seeded into the database.
type RoleTemplate struct {
	Name        string
	Description string
	Audience    domain.UserKind
	// System roles are owned by the code: permissions are re-synced on every
	// seed and the API cannot change them. Non-system templates are created
	// once and can then be customised by admins.
	System      bool
	Permissions []domain.Permission
}

// DefaultRoles are seeded on every `seed`.
var DefaultRoles = []RoleTemplate{
	{
		Name:        RoleAdmin,
		Description: "Full access to every operation",
		Audience:    domain.UserKindInternal,
		System:      true,
		Permissions: AllPermissions(),
	},
	{
		Name:        RoleManager,
		Description: "Manages users and their access",
		Audience:    domain.UserKindInternal,
		Permissions: []domain.Permission{UsersRead, UsersCreate, UsersUpdate, UsersAssignRoles, RolesRead},
	},
	{
		Name:        RoleViewer,
		Description: "Read-only access to users and roles",
		Audience:    domain.UserKindInternal,
		Permissions: []domain.Permission{UsersRead, RolesRead},
	},
	{
		Name:        RoleAuditor,
		Description: "Reads the audit log",
		Audience:    domain.UserKindInternal,
		Permissions: []domain.Permission{UsersRead, RolesRead, AuditRead},
	},
	// Optional public role example, for a type that needs permissions:
	// {Name: "vendor", Audience: domain.UserKindPublic, System: true,
	//  Permissions: []domain.Permission{ProductsManage}},
}

// Public user types. Rename or extend to fit the application; a user may
// hold several (e.g. both customer and vendor).
const (
	PublicTypeCustomer = "customer"
	PublicTypeVendor   = "vendor"
)

// DefaultPublicType is used when a sign-up does not choose a type.
const DefaultPublicType = PublicTypeCustomer

// PublicUserTypes is the registry of public user types.
var PublicUserTypes = []domain.PublicUserType{
	{Name: PublicTypeCustomer, Description: "Regular user of the application", SelfRegistration: true},
	{Name: PublicTypeVendor, Description: "Business partner, onboarded by staff", SelfRegistration: false},
}

// AllPermissions returns every permission code in the registry.
func AllPermissions() []domain.Permission {
	out := make([]domain.Permission, len(Permissions))
	for i, p := range Permissions {
		out[i] = p.Code
	}
	return out
}

// IsKnown reports whether p is in the registry.
func IsKnown(p domain.Permission) bool {
	for _, def := range Permissions {
		if def.Code == p {
			return true
		}
	}
	return false
}

// LookupPublicType returns the public user type with the given name.
func LookupPublicType(name string) (domain.PublicUserType, bool) {
	for _, t := range PublicUserTypes {
		if t.Name == name {
			return t, true
		}
	}
	return domain.PublicUserType{}, false
}
