// Package sso defines the extension points for single sign-on with external
// identity providers (OpenID Connect, OAuth 2.0, SAML via a bridge).
//
// No provider is integrated yet. To add one, implement Provider (typically
// with github.com/coreos/go-oidc and golang.org/x/oauth2), choose a Policy
// and register both in app.ProvideSSORegistry. The HTTP flow (state, nonce,
// PKCE, callback) and account linking are already implemented.
// See docs/sso.md.
package sso

import (
	"context"
	"errors"
	"sort"

	"github.com/MhmdRyhn/gate/internal/domain"
)

// Identity is what a provider asserts about the signed-in user after the
// provider's token has been fully verified.
type Identity struct {
	Provider      string
	Subject       string // stable, provider-unique user ID ("sub")
	Email         string
	EmailVerified bool // only trust email for linking when the IdP verified it
	Name          string
}

// Provider is one external identity provider using the authorization code
// flow.
type Provider interface {
	// Name is the URL-safe registry key, e.g. "google".
	Name() string
	// AuthCodeURL returns the provider's authorization URL. state and
	// nonce must be passed through unchanged; codeChallenge is the PKCE
	// S256 challenge.
	AuthCodeURL(state, nonce, codeChallenge string) string
	// Exchange trades the authorization code for tokens, verifies them
	// (signature, issuer, audience, expiry, nonce) and returns the identity.
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (*Identity, error)
}

// Policy decides who may sign in through a provider and what happens on
// first sign-in. The defaults are deny-by-default.
type Policy struct {
	// Kind of user this provider serves. A staff IdP (e.g. Entra ID) uses
	// internal; a consumer IdP (e.g. Google, Apple) uses public.
	Kind domain.UserKind
	// AllowSignup creates a new public user on first sign-in. Never
	// applies to internal users: staff accounts are provisioned by admins.
	AllowSignup bool
	// SignupPublicType is the public type given to users created by
	// AllowSignup. Must allow self-registration.
	SignupPublicType string
	// LinkVerifiedEmail links the identity to an existing account with the
	// same email if the IdP says the email is verified. Enable only for
	// IdPs that are authoritative for their users' emails.
	LinkVerifiedEmail bool
}

// Registration is a provider with its policy.
type Registration struct {
	Provider Provider
	Policy   Policy
}

// ErrUnknownProvider is returned for unregistered provider names.
var ErrUnknownProvider = errors.New("unknown SSO provider")

// Registry holds the enabled providers.
type Registry struct {
	entries map[string]Registration
}

// NewRegistry returns a registry of the given providers.
func NewRegistry(regs ...Registration) *Registry {
	r := &Registry{entries: map[string]Registration{}}
	for _, reg := range regs {
		r.entries[reg.Provider.Name()] = reg
	}
	return r
}

// Get returns the registration for name.
func (r *Registry) Get(name string) (Registration, error) {
	reg, ok := r.entries[name]
	if !ok {
		return Registration{}, ErrUnknownProvider
	}
	return reg, nil
}

// Names lists the registered providers, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.entries))
	for n := range r.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Empty reports whether no provider is registered.
func (r *Registry) Empty() bool { return len(r.entries) == 0 }
