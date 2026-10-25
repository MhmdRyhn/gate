package httpapi

import (
	"time"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/service"
)

// Request and response bodies. DTOs decouple the public API contract from
// domain and storage models: internal fields (password hashes, token
// hashes) cannot leak because they have no DTO field. Size limits bound
// the work an attacker can cause per request.

type loginRequest struct {
	Identifier string `json:"identifier" binding:"required,max=320"` // email or phone
	Password   string `json:"password" binding:"required,max=512"`
}

type registerRequest struct {
	Email    string `json:"email" binding:"max=254"`
	Phone    string `json:"phone" binding:"max=32"`
	FullName string `json:"full_name" binding:"max=200"`
	Password string `json:"password" binding:"required,max=512"`
	Type     string `json:"type" binding:"max=50"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,max=256"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=512"`
	NewPassword     string `json:"new_password" binding:"required,max=512"`
}

type createUserRequest struct {
	Email       string      `json:"email" binding:"max=254"`
	Phone       string      `json:"phone" binding:"max=32"`
	FullName    string      `json:"full_name" binding:"max=200"`
	Password    string      `json:"password" binding:"required,max=512"`
	Kind        string      `json:"kind" binding:"omitempty,oneof=internal public"`
	RoleIDs     []uuid.UUID `json:"role_ids" binding:"max=50"`
	PublicTypes []string    `json:"public_types" binding:"max=10,dive,max=50"`
}

type updateUserRequest struct {
	FullName *string `json:"full_name" binding:"omitempty,max=200"`
	Status   *string `json:"status" binding:"omitempty,oneof=active disabled"`
}

type setRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required,max=50"`
}

type setPublicTypesRequest struct {
	PublicTypes []string `json:"public_types" binding:"required,min=1,max=10,dive,required,max=50"`
}

type roleRequest struct {
	Name        *string   `json:"name" binding:"omitempty,max=50"`
	Description *string   `json:"description" binding:"omitempty,max=500"`
	Permissions *[]string `json:"permissions" binding:"omitempty,max=200,dive,max=100"`
}

// tokenResponse follows the OAuth 2.0 token response shape (RFC 6749 §5.1).
type tokenResponse struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

func newTokenResponse(p *service.TokenPair) tokenResponse {
	now := time.Now()
	return tokenResponse{
		TokenType:        "Bearer",
		AccessToken:      p.AccessToken,
		ExpiresIn:        int64(p.AccessTokenExpiresAt.Sub(now).Seconds()),
		RefreshToken:     p.RefreshToken,
		RefreshExpiresIn: int64(p.RefreshTokenExpiresAt.Sub(now).Seconds()),
	}
}

type userResponse struct {
	ID              uuid.UUID      `json:"id"`
	Email           *string        `json:"email,omitempty"`
	Phone           *string        `json:"phone,omitempty"`
	FullName        string         `json:"full_name"`
	Kind            string         `json:"kind"`
	Status          string         `json:"status"`
	PublicTypes     []string       `json:"public_types,omitempty"`
	HasPassword     bool           `json:"has_password"`
	EmailVerifiedAt *time.Time     `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt *time.Time     `json:"phone_verified_at,omitempty"`
	LastLoginAt     *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	Roles           []roleResponse `json:"roles,omitempty"`
}

func newUserResponse(u *domain.User, roles []domain.Role) userResponse {
	r := userResponse{
		ID: u.ID, Email: u.Email, Phone: u.Phone, FullName: u.FullName, Kind: string(u.Kind), Status: string(u.Status),
		PublicTypes: u.PublicTypes, HasPassword: u.PasswordHash != "",
		EmailVerifiedAt: u.EmailVerifiedAt, PhoneVerifiedAt: u.PhoneVerifiedAt, LastLoginAt: u.LastLoginAt,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
	for _, role := range roles {
		r.Roles = append(r.Roles, newRoleResponse(&role))
	}
	return r
}

func newUserDetailsResponse(d *service.UserDetails) userResponse {
	r := newUserResponse(d.User, d.Roles)
	if r.Roles == nil {
		r.Roles = []roleResponse{}
	}
	return r
}

type meResponse struct {
	userResponse
	SessionID   uuid.UUID `json:"session_id"`
	Permissions []string  `json:"permissions"`
}

type roleResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Audience    string    `json:"audience"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func newRoleResponse(r *domain.Role) roleResponse {
	perms := make([]string, len(r.Permissions))
	for i, p := range r.Permissions {
		perms[i] = string(p)
	}
	return roleResponse{ID: r.ID, Name: r.Name, Description: r.Description, Audience: string(r.Audience),
		IsSystem: r.IsSystem, Permissions: perms, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

type auditEventResponse struct {
	ID          uuid.UUID      `json:"id"`
	OccurredAt  time.Time      `json:"occurred_at"`
	ActorUserID *uuid.UUID     `json:"actor_user_id,omitempty"`
	Action      string         `json:"action"`
	TargetType  string         `json:"target_type,omitempty"`
	TargetID    string         `json:"target_id,omitempty"`
	IP          string         `json:"ip,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type listResponse[T any] struct {
	Items  []T `json:"items"`
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}
