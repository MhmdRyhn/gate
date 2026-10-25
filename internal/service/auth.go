package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/auth"
	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/repository"
	"github.com/MhmdRyhn/gate/internal/requestctx"
)

// TokenPair is the result of a successful sign-in or refresh.
type TokenPair struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	SessionID             uuid.UUID
}

// AuthService handles password sign-in, registration, sessions and access
// token verification.
type AuthService struct {
	users    repository.UserRepository
	sessions repository.SessionRepository
	hasher   *auth.PasswordHasher
	tokens   *auth.TokenIssuer
	audit    *Auditor
	cfg      config.AuthConfig
	log      *zap.Logger
	now      func() time.Time
}

// NewAuthService wires an AuthService.
func NewAuthService(users repository.UserRepository, sessions repository.SessionRepository, hasher *auth.PasswordHasher,
	tokens *auth.TokenIssuer, audit *Auditor, cfg config.AuthConfig, log *zap.Logger) *AuthService {
	return &AuthService{users: users, sessions: sessions, hasher: hasher, tokens: tokens, audit: audit, cfg: cfg, log: log, now: time.Now}
}

// Authenticate verifies an access token and loads the principal. It fails
// if the token is invalid, its session was revoked or expired, or the user
// was disabled — so logout and disabling take effect immediately.
func (s *AuthService) Authenticate(ctx context.Context, rawToken string) (*domain.Principal, error) {
	claims, err := s.tokens.Parse(rawToken)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	userID, _ := uuid.Parse(claims.Subject)
	sessionID, _ := uuid.Parse(claims.SessionID)
	p, err := s.users.GetPrincipal(ctx, userID, sessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if p.Kind != claims.Kind { // kind is immutable; a mismatch means a forged or corrupted token
		return nil, domain.ErrInvalidToken
	}
	return p, nil
}

// Login signs in with an email address or phone number and a password.
func (s *AuthService) Login(ctx context.Context, identifier, password string) (*TokenPair, error) {
	u, err := s.findByIdentifier(ctx, identifier)
	if errors.Is(err, domain.ErrNotFound) {
		s.hasher.VerifyDummy(password)
		s.audit.Record(ctx, AuditEntry{Action: AuditLoginFailed, Details: map[string]any{"reason": "unknown_identifier"}})
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if u.PasswordHash == "" { // SSO-only account
		s.hasher.VerifyDummy(password)
		s.audit.Record(ctx, AuditEntry{Action: AuditLoginFailed, TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"reason": "no_password"}})
		return nil, domain.ErrInvalidCredentials
	}
	ok, rehash := s.hasher.Verify(u.PasswordHash, password)
	if !ok {
		s.audit.Record(ctx, AuditEntry{Action: AuditLoginFailed, TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"reason": "bad_password"}})
		return nil, domain.ErrInvalidCredentials
	}
	if u.Status != domain.UserStatusActive {
		s.audit.Record(ctx, AuditEntry{Action: AuditLoginFailed, TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"reason": "disabled"}})
		return nil, domain.ErrUserDisabled
	}
	if rehash {
		s.upgradeHash(ctx, u.ID, password)
	}
	pair, err := s.StartSession(ctx, u, "password")
	if err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditLoginSucceeded, TargetType: "session", TargetID: pair.SessionID.String()})
	return pair, nil
}

// RegisterInput is a public self-registration.
type RegisterInput struct {
	Email, Phone, FullName, Password string
	// Type defaults to rbac.DefaultPublicType and must allow self-registration.
	Type string
}

// Register creates a public user and signs them in.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*TokenPair, error) {
	if !s.cfg.PublicRegistrationEnabled {
		return nil, fmt.Errorf("%w: registration is disabled", domain.ErrForbidden)
	}
	if in.Type == "" {
		in.Type = rbac.DefaultPublicType
	}
	t, ok := rbac.LookupPublicType(in.Type)
	if !ok {
		return nil, domain.Invalid("unknown type %q", in.Type)
	}
	if !t.SelfRegistration {
		return nil, fmt.Errorf("%w: type %q cannot self-register", domain.ErrForbidden, in.Type)
	}
	u, err := s.newUser(in.Email, in.Phone, in.FullName, in.Password, domain.UserKindPublic)
	if err != nil {
		return nil, err
	}
	if err := createUser(ctx, s.users, u, repository.CreateUserOptions{PublicTypes: []string{t.Name}}); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditRegistered, TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"type": t.Name}})
	return s.StartSession(ctx, u, "password")
}

// Refresh exchanges a refresh token for a new token pair (rotation).
// Presenting an already-used token signals theft: the whole session is
// revoked, logging out both the attacker and the victim (RFC 6819 §5.2.2.3).
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	rt, sess, err := s.sessions.GetByRefreshToken(ctx, auth.HashOpaqueToken(refreshToken))
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if rt.UsedAt != nil {
		if err := s.sessions.Revoke(ctx, sess.ID); err != nil {
			return nil, err
		}
		s.log.Warn("refresh token reuse detected; session revoked", zap.String("session_id", sess.ID.String()))
		s.audit.Record(ctx, AuditEntry{Actor: &sess.UserID, Action: AuditRefreshReuse, TargetType: "session", TargetID: sess.ID.String()})
		return nil, domain.ErrInvalidToken
	}
	if !sess.Active(now) || now.After(rt.ExpiresAt) {
		return nil, domain.ErrInvalidToken
	}
	u, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Status != domain.UserStatusActive {
		return nil, domain.ErrUserDisabled
	}

	plain, hash, err := auth.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	next := &domain.RefreshToken{ID: newID(), SessionID: sess.ID, TokenHash: hash, ExpiresAt: s.refreshExpiry(now, sess)}
	if err := s.sessions.Rotate(ctx, rt.ID, next); err != nil {
		return nil, err
	}
	access, accessExp, err := s.tokens.Issue(u.ID, sess.ID, u.Kind)
	if err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: access, AccessTokenExpiresAt: accessExp, RefreshToken: plain, RefreshTokenExpiresAt: next.ExpiresAt, SessionID: sess.ID}, nil
}

// Logout revokes the session of a refresh token. Unknown tokens are ignored
// so the endpoint does not reveal token validity.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	_, sess, err := s.sessions.GetByRefreshToken(ctx, auth.HashOpaqueToken(refreshToken))
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.sessions.Revoke(ctx, sess.ID); err != nil {
		return err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &sess.UserID, Action: AuditLogout, TargetType: "session", TargetID: sess.ID.String()})
	return nil
}

// LogoutAll revokes every session of the principal, including the current one.
func (s *AuthService) LogoutAll(ctx context.Context, p *domain.Principal) error {
	if err := s.sessions.RevokeAllForUser(ctx, p.UserID, nil); err != nil {
		return err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &p.UserID, Action: AuditLogoutAll, TargetType: "user", TargetID: p.UserID.String()})
	return nil
}

// ChangePassword verifies the current password, stores the new one and
// signs out every other session.
func (s *AuthService) ChangePassword(ctx context.Context, p *domain.Principal, current, next string) error {
	u, err := s.users.GetByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if u.PasswordHash == "" {
		return domain.Invalid("this account signs in with SSO and has no password")
	}
	if ok, _ := s.hasher.Verify(u.PasswordHash, current); !ok {
		return domain.ErrInvalidCredentials
	}
	if err := auth.ValidatePassword(next); err != nil {
		return domain.Invalid("%s", err.Error())
	}
	hash, err := s.hasher.Hash(next)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.sessions.RevokeAllForUser(ctx, u.ID, &p.SessionID); err != nil {
		return err
	}
	s.audit.Record(ctx, AuditEntry{Actor: &u.ID, Action: AuditPasswordChanged, TargetType: "user", TargetID: u.ID.String()})
	return nil
}

// PurgeSessions deletes sessions and refresh tokens that ended before t.
func (s *AuthService) PurgeSessions(ctx context.Context, before time.Time) (int64, error) {
	return s.sessions.Purge(ctx, before)
}

// StartSession creates a session for u and returns its first token pair.
// method is "password" or "sso:<provider>".
func (s *AuthService) StartSession(ctx context.Context, u *domain.User, method string) (*TokenPair, error) {
	now := s.now()
	meta := requestctx.From(ctx)
	sess := &domain.Session{
		ID: newID(), UserID: u.ID, AuthMethod: method, IP: meta.IP, UserAgent: truncate(meta.UserAgent, 512),
		ExpiresAt: now.Add(s.cfg.SessionMaxLifetime),
	}
	plain, hash, err := auth.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	rt := &domain.RefreshToken{ID: newID(), SessionID: sess.ID, TokenHash: hash, ExpiresAt: s.refreshExpiry(now, sess)}
	if err := s.sessions.Create(ctx, sess, rt); err != nil {
		return nil, err
	}
	access, accessExp, err := s.tokens.Issue(u.ID, sess.ID, u.Kind)
	if err != nil {
		return nil, err
	}
	if err := s.users.TouchLastLogin(ctx, u.ID); err != nil {
		s.log.Warn("update last login", zap.String("user_id", u.ID.String()), zap.Error(err))
	}
	return &TokenPair{AccessToken: access, AccessTokenExpiresAt: accessExp, RefreshToken: plain, RefreshTokenExpiresAt: rt.ExpiresAt, SessionID: sess.ID}, nil
}

// refreshExpiry is the idle timeout, capped by the session's absolute lifetime.
func (s *AuthService) refreshExpiry(now time.Time, sess *domain.Session) time.Time {
	exp := now.Add(s.cfg.RefreshTokenTTL)
	if exp.After(sess.ExpiresAt) {
		return sess.ExpiresAt
	}
	return exp
}

// newUser validates the fields shared by every way of creating a user.
func (s *AuthService) newUser(email, phone, fullName, password string, kind domain.UserKind) (*domain.User, error) {
	e, p, err := contactInput(email, phone)
	if err != nil {
		return nil, err
	}
	name, err := cleanFullName(fullName)
	if err != nil {
		return nil, err
	}
	if err := auth.ValidatePassword(password); err != nil {
		return nil, domain.Invalid("%s", err.Error())
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	return &domain.User{ID: newID(), Email: e, Phone: p, FullName: name, PasswordHash: hash, Kind: kind, Status: domain.UserStatusActive}, nil
}

// findByIdentifier treats identifiers containing "@" as emails and anything
// else as phone numbers.
func (s *AuthService) findByIdentifier(ctx context.Context, identifier string) (*domain.User, error) {
	if strings.Contains(identifier, "@") {
		email, err := normalizeEmail(identifier)
		if err != nil {
			return nil, domain.ErrNotFound
		}
		return s.users.GetByEmail(ctx, email)
	}
	phone, err := normalizePhone(identifier)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	return s.users.GetByPhone(ctx, phone)
}

func (s *AuthService) upgradeHash(ctx context.Context, id uuid.UUID, password string) {
	hash, err := s.hasher.Hash(password)
	if err == nil {
		err = s.users.UpdatePassword(ctx, id, hash)
	}
	if err != nil {
		s.log.Warn("password rehash failed", zap.String("user_id", id.String()), zap.Error(err))
	}
}

func createUser(ctx context.Context, users repository.UserRepository, u *domain.User, opts repository.CreateUserOptions) error {
	err := users.Create(ctx, u, opts)
	if errors.Is(err, domain.ErrConflict) {
		return fmt.Errorf("%w: email or phone already registered", domain.ErrConflict)
	}
	return err
}
