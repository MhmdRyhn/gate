package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// IdentityRepository implements repository.IdentityRepository.
type IdentityRepository struct{ db *gorm.DB }

var _ repository.IdentityRepository = (*IdentityRepository)(nil)

// NewIdentityRepository returns a gorm-backed SSO identity repository.
func NewIdentityRepository(db *gorm.DB) *IdentityRepository { return &IdentityRepository{db: db} }

// FindUser returns the user linked to (provider, subject) and records the use.
func (r *IdentityRepository) FindUser(ctx context.Context, provider, subject string) (*domain.User, error) {
	db := r.db.WithContext(ctx)
	var link userIdentityModel
	if err := db.Where("provider = ? AND subject = ?", provider, subject).Take(&link).Error; err != nil {
		return nil, mapErr(err)
	}
	var u userModel
	if err := db.Preload("PublicTypes").Where("id = ?", link.UserID).Take(&u).Error; err != nil {
		return nil, mapErr(err)
	}
	db.Model(&link).Update("last_used_at", time.Now().UTC())
	return u.toDomain(), nil
}

// Link attaches an SSO identity to an existing user.
func (r *IdentityRepository) Link(ctx context.Context, id *domain.UserIdentity) error {
	return mapErr(r.db.WithContext(ctx).Create(&userIdentityModel{
		ID: id.ID, UserID: id.UserID, Provider: id.Provider, Subject: id.Subject, Email: id.Email,
	}).Error)
}

// AuditRepository implements repository.AuditRepository.
type AuditRepository struct{ db *gorm.DB }

var _ repository.AuditRepository = (*AuditRepository)(nil)

// NewAuditRepository returns a gorm-backed audit log.
func NewAuditRepository(db *gorm.DB) *AuditRepository { return &AuditRepository{db: db} }

// Record appends an event.
func (r *AuditRepository) Record(ctx context.Context, e *domain.AuditEvent) error {
	m, err := toAuditModel(e)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(m).Error
}

// List returns events, newest first.
func (r *AuditRepository) List(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEvent, error) {
	q := r.db.WithContext(ctx).Model(&auditEventModel{})
	if f.ActorUserID != nil {
		q = q.Where("actor_user_id = ?", *f.ActorUserID)
	}
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
	}
	var ms []auditEventModel
	if err := q.Order("occurred_at DESC, id DESC").Limit(f.Limit).Offset(f.Offset).Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AuditEvent, len(ms))
	for i := range ms {
		out[i] = ms[i].toDomain()
	}
	return out, nil
}
