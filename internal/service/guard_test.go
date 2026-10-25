package service

import (
	"errors"
	"testing"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
)

func TestEnsureHolds(t *testing.T) {
	manager := &domain.Principal{Permissions: domain.NewPermissionSet(rbac.UsersRead, rbac.UsersAssignRoles)}
	if err := ensureHolds(manager, []domain.Permission{rbac.UsersRead}); err != nil {
		t.Errorf("subset rejected: %v", err)
	}
	if err := ensureHolds(manager, []domain.Permission{rbac.UsersRead, rbac.RolesManage}); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("escalation allowed: %v", err)
	}
}

func TestCleanPermissions(t *testing.T) {
	got, err := cleanPermissions([]domain.Permission{rbac.UsersRead, rbac.RolesRead, rbac.UsersRead})
	if err != nil || len(got) != 2 || got[0] != rbac.RolesRead {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := cleanPermissions([]domain.Permission{"made:up"}); err == nil {
		t.Error("unknown permission accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got, err := normalizeEmail("  Alice@Example.COM "); err != nil || got != "alice@example.com" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "nope", "Alice <alice@example.com>"} {
		if _, err := normalizeEmail(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	for in, want := range map[string]string{
		"+8801712345678":    "+8801712345678",
		"+880 1712-345678":  "+8801712345678",
		"00880 1712 345678": "+8801712345678",
		"+1 (415) 555-0100": "+14155550100",
	} {
		if got, err := normalizePhone(in); err != nil || got != want {
			t.Errorf("normalizePhone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "01712345678", "+0123456789", "+12", "+1234567890123456", "+88017abc"} {
		if _, err := normalizePhone(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestContactInput(t *testing.T) {
	if _, _, err := contactInput("", " "); err == nil {
		t.Error("missing email and phone accepted")
	}
	e, p, err := contactInput("A@B.io", "+8801712345678")
	if err != nil || *e != "a@b.io" || *p != "+8801712345678" {
		t.Errorf("both: %v %v %v", e, p, err)
	}
}
