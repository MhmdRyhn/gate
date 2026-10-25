package rbac

import (
	"regexp"
	"testing"

	"github.com/MhmdRyhn/gate/internal/domain"
)

// Must match the CHECK constraint on permissions.code in the schema.
var codeFormat = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)

func TestPermissionRegistry(t *testing.T) {
	seen := map[domain.Permission]bool{}
	for _, p := range Permissions {
		if !codeFormat.MatchString(string(p.Code)) {
			t.Errorf("permission %q does not match <resource>:<action>", p.Code)
		}
		if seen[p.Code] {
			t.Errorf("duplicate permission %q", p.Code)
		}
		seen[p.Code] = true
	}
}

func TestDefaultRoles(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range DefaultRoles {
		if seen[r.Name] {
			t.Errorf("duplicate role %q", r.Name)
		}
		seen[r.Name] = true
		if !r.Audience.Valid() {
			t.Errorf("role %q: invalid audience", r.Name)
		}
		if r.Audience == domain.UserKindPublic && !r.System {
			t.Errorf("public role %q must be a system role", r.Name)
		}
		for _, p := range r.Permissions {
			if !IsKnown(p) {
				t.Errorf("role %q references unknown permission %q", r.Name, p)
			}
		}
	}
}

func TestPublicUserTypes(t *testing.T) {
	roles := map[string]RoleTemplate{}
	for _, r := range DefaultRoles {
		roles[r.Name] = r
	}
	seen := map[string]bool{}
	for _, pt := range PublicUserTypes {
		if seen[pt.Name] {
			t.Errorf("duplicate public type %q", pt.Name)
		}
		seen[pt.Name] = true
		if pt.Role != "" {
			if r, ok := roles[pt.Role]; !ok || r.Audience != domain.UserKindPublic {
				t.Errorf("public type %q must reference a public role, got %q", pt.Name, pt.Role)
			}
		}
	}
	if d, ok := LookupPublicType(DefaultPublicType); !ok || !d.SelfRegistration {
		t.Errorf("DefaultPublicType %q must exist and allow self-registration", DefaultPublicType)
	}
}
