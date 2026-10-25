package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MhmdRyhn/gate/internal/auth/sso"
	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// SSOService turns a verified external identity into a local session,
// following the provider's Policy. See docs/sso.md.
type SSOService struct {
	registry   *sso.Registry
	users      repository.UserRepository
	identities repository.IdentityRepository
	auth       *AuthService
	audit      *Auditor
}

// NewSSOService wires an SSOService.
func NewSSOService(registry *sso.Registry, users repository.UserRepository, identities repository.IdentityRepository, auth *AuthService, audit *Auditor) *SSOService {
	return &SSOService{registry: registry, users: users, identities: identities, auth: auth, audit: audit}
}

// SignIn resolves the identity to a user, in this order:
//  1. an existing link (provider, subject);
//  2. if the policy allows, an existing account with the same verified email,
//     which is then linked;
//  3. if the policy allows, a new public user.
//
// Anything else is rejected: deny by default.
func (s *SSOService) SignIn(ctx context.Context, providerName string, id *sso.Identity) (*TokenPair, error) {
	reg, err := s.registry.Get(providerName)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	if id == nil || id.Subject == "" || id.Provider != providerName {
		return nil, domain.ErrInvalidCredentials
	}
	policy := reg.Policy
	method := "sso:" + providerName

	u, err := s.identities.FindUser(ctx, providerName, id.Subject)
	switch {
	case err == nil:
	case errors.Is(err, domain.ErrNotFound):
		u, err = s.linkOrCreate(ctx, policy, id)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if u.Kind != policy.Kind {
		return nil, fmt.Errorf("%w: this provider is not enabled for %s users", domain.ErrForbidden, u.Kind)
	}
	if u.Status != domain.UserStatusActive {
		return nil, domain.ErrUserDisabled
	}
	pair, err := s.auth.StartSession(ctx, u, method)
	if err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditSSOLogin, TargetType: "session", TargetID: pair.SessionID.String(),
		Details: map[string]any{"provider": providerName}})
	return pair, nil
}

func (s *SSOService) linkOrCreate(ctx context.Context, policy sso.Policy, id *sso.Identity) (*domain.User, error) {
	var email string
	if id.Email != "" && id.EmailVerified {
		if e, err := normalizeEmail(id.Email); err == nil {
			email = e
		}
	}

	// Link to an existing account only when the IdP vouches for the email.
	if policy.LinkVerifiedEmail && email != "" {
		u, err := s.users.GetByEmail(ctx, email)
		if err == nil {
			if u.Kind != policy.Kind {
				return nil, domain.ErrInvalidCredentials
			}
			link := &domain.UserIdentity{ID: newID(), UserID: u.ID, Provider: id.Provider, Subject: id.Subject, Email: email}
			if err := s.identities.Link(ctx, link); err != nil {
				return nil, err
			}
			s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditSSOLinked, TargetType: "user", TargetID: u.ID.String(),
				Details: map[string]any{"provider": id.Provider}})
			return u, nil
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
	}

	// Staff accounts are never created implicitly.
	if !policy.AllowSignup || policy.Kind != domain.UserKindPublic {
		return nil, fmt.Errorf("%w: no account is linked to this identity", domain.ErrForbidden)
	}
	t, ok := rbac.LookupPublicType(policy.SignupPublicType)
	if !ok || !t.SelfRegistration {
		return nil, fmt.Errorf("SSO policy for %s: public type %q cannot self-register", id.Provider, policy.SignupPublicType)
	}
	if email == "" {
		// The schema requires an email or phone; unverified emails are never
		// stored as identifiers because they could block the real owner.
		return nil, domain.Invalid("the identity provider did not supply a verified email")
	}
	name, _ := cleanFullName(id.Name)
	now := time.Now().UTC()
	u := &domain.User{ID: newID(), Email: &email, EmailVerifiedAt: &now, FullName: name, Kind: domain.UserKindPublic, Status: domain.UserStatusActive}
	identity := &domain.UserIdentity{ID: newID(), Provider: id.Provider, Subject: id.Subject, Email: email}
	if err := createUser(ctx, s.users, u, repository.CreateUserOptions{PublicTypes: []string{t.Name}, Identity: identity}); err != nil {
		return nil, err
	}
	u.PublicTypes = []string{t.Name}
	s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditRegistered, TargetType: "user", TargetID: u.ID.String(),
		Details: map[string]any{"type": t.Name, "provider": id.Provider}})
	return u, nil
}
