package postgres

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/MhmdRyhn/gate/internal/domain"
)

// Persistence models mirror the SQL schema. They are private to this package
// and mapped to domain entities, so storage concerns (tags, nullability)
// never leak into business logic or API responses.

type userModel struct {
	ID              uuid.UUID `gorm:"primaryKey"`
	Email           *string
	Phone           *string
	FullName        string
	PasswordHash    *string
	Kind            string
	Status          string
	EmailVerifiedAt *time.Time
	PhoneVerifiedAt *time.Time
	LastLoginAt     *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	PublicTypes     []userPublicTypeModel `gorm:"foreignKey:UserID"`
}

func (userModel) TableName() string { return "users" }

type userPublicTypeModel struct {
	UserID    uuid.UUID `gorm:"primaryKey"`
	TypeName  string    `gorm:"primaryKey"`
	GrantedAt time.Time `gorm:"autoCreateTime"`
}

func (userPublicTypeModel) TableName() string { return "user_public_types" }

type userRoleModel struct {
	UserID    uuid.UUID `gorm:"primaryKey"`
	RoleID    uuid.UUID `gorm:"primaryKey"`
	GrantedAt time.Time `gorm:"autoCreateTime"`
}

func (userRoleModel) TableName() string { return "user_roles" }

type roleModel struct {
	ID          uuid.UUID `gorm:"primaryKey"`
	Name        string
	Description string
	Audience    string
	IsSystem    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Permissions []rolePermissionModel `gorm:"foreignKey:RoleID"`
}

func (roleModel) TableName() string { return "roles" }

type rolePermissionModel struct {
	RoleID         uuid.UUID `gorm:"primaryKey"`
	PermissionCode string    `gorm:"primaryKey"`
}

func (rolePermissionModel) TableName() string { return "role_permissions" }

type permissionModel struct {
	Code        string `gorm:"primaryKey"`
	Description string
}

func (permissionModel) TableName() string { return "permissions" }

type publicUserTypeModel struct {
	Name             string `gorm:"primaryKey"`
	Description      string
	RoleID           *uuid.UUID
	SelfRegistration bool
}

func (publicUserTypeModel) TableName() string { return "public_user_types" }

type userIdentityModel struct {
	ID         uuid.UUID `gorm:"primaryKey"`
	UserID     uuid.UUID
	Provider   string
	Subject    string
	Email      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func (userIdentityModel) TableName() string { return "user_identities" }

type sessionModel struct {
	ID              uuid.UUID `gorm:"primaryKey"`
	UserID          uuid.UUID
	AuthMethod      string
	IP              string
	UserAgent       string
	CreatedAt       time.Time
	LastRefreshedAt time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func (sessionModel) TableName() string { return "sessions" }

type refreshTokenModel struct {
	ID        uuid.UUID `gorm:"primaryKey"`
	SessionID uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (refreshTokenModel) TableName() string { return "refresh_tokens" }

type auditEventModel struct {
	ID          uuid.UUID `gorm:"primaryKey"`
	OccurredAt  time.Time
	ActorUserID *uuid.UUID
	Action      string
	TargetType  string
	TargetID    string
	IP          string
	UserAgent   string
	RequestID   string
	Details     string `gorm:"type:jsonb"`
}

func (auditEventModel) TableName() string { return "audit_events" }

// --- mapping ----------------------------------------------------------------

func toUserModel(u *domain.User) *userModel {
	m := &userModel{
		ID: u.ID, Email: u.Email, Phone: u.Phone, FullName: u.FullName,
		Kind: string(u.Kind), Status: string(u.Status),
		EmailVerifiedAt: u.EmailVerifiedAt, PhoneVerifiedAt: u.PhoneVerifiedAt,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
	if u.PasswordHash != "" {
		m.PasswordHash = &u.PasswordHash
	}
	return m
}

func (m *userModel) toDomain() *domain.User {
	u := &domain.User{
		ID: m.ID, Email: m.Email, Phone: m.Phone, FullName: m.FullName,
		Kind: domain.UserKind(m.Kind), Status: domain.UserStatus(m.Status),
		EmailVerifiedAt: m.EmailVerifiedAt, PhoneVerifiedAt: m.PhoneVerifiedAt, LastLoginAt: m.LastLoginAt,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, PublicTypes: []string{},
	}
	if m.PasswordHash != nil {
		u.PasswordHash = *m.PasswordHash
	}
	for _, t := range m.PublicTypes {
		u.PublicTypes = append(u.PublicTypes, t.TypeName)
	}
	return u
}

func (m *roleModel) toDomain() domain.Role {
	r := domain.Role{
		ID: m.ID, Name: m.Name, Description: m.Description, Audience: domain.UserKind(m.Audience),
		IsSystem: m.IsSystem, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
		Permissions: make([]domain.Permission, 0, len(m.Permissions)),
	}
	for _, p := range m.Permissions {
		r.Permissions = append(r.Permissions, domain.Permission(p.PermissionCode))
	}
	return r
}

func (m *sessionModel) toDomain() *domain.Session {
	return &domain.Session{
		ID: m.ID, UserID: m.UserID, AuthMethod: m.AuthMethod, IP: m.IP, UserAgent: m.UserAgent,
		CreatedAt: m.CreatedAt, LastRefreshedAt: m.LastRefreshedAt, ExpiresAt: m.ExpiresAt, RevokedAt: m.RevokedAt,
	}
}

func (m *refreshTokenModel) toDomain() *domain.RefreshToken {
	return &domain.RefreshToken{
		ID: m.ID, SessionID: m.SessionID, TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, UsedAt: m.UsedAt, CreatedAt: m.CreatedAt,
	}
}

func toAuditModel(e *domain.AuditEvent) (*auditEventModel, error) {
	details := "{}"
	if len(e.Details) > 0 {
		b, err := json.Marshal(e.Details)
		if err != nil {
			return nil, err
		}
		details = string(b)
	}
	return &auditEventModel{
		ID: e.ID, OccurredAt: e.OccurredAt, ActorUserID: e.ActorUserID, Action: e.Action,
		TargetType: e.TargetType, TargetID: e.TargetID, IP: e.IP, UserAgent: e.UserAgent,
		RequestID: e.RequestID, Details: details,
	}, nil
}

func (m *auditEventModel) toDomain() domain.AuditEvent {
	e := domain.AuditEvent{
		ID: m.ID, OccurredAt: m.OccurredAt, ActorUserID: m.ActorUserID, Action: m.Action,
		TargetType: m.TargetType, TargetID: m.TargetID, IP: m.IP, UserAgent: m.UserAgent, RequestID: m.RequestID,
	}
	_ = json.Unmarshal([]byte(m.Details), &e.Details)
	return e
}
