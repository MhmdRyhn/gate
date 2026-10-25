package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// SessionRepository implements repository.SessionRepository.
type SessionRepository struct{ db *gorm.DB }

var _ repository.SessionRepository = (*SessionRepository)(nil)

// NewSessionRepository returns a gorm-backed session repository.
func NewSessionRepository(db *gorm.DB) *SessionRepository { return &SessionRepository{db: db} }

// Create stores a session and its first refresh token atomically.
func (r *SessionRepository) Create(ctx context.Context, s *domain.Session, rt *domain.RefreshToken) error {
	sm := &sessionModel{
		ID: s.ID, UserID: s.UserID, AuthMethod: s.AuthMethod, IP: s.IP, UserAgent: s.UserAgent,
		LastRefreshedAt: time.Now().UTC(), ExpiresAt: s.ExpiresAt,
	}
	tm := &refreshTokenModel{ID: rt.ID, SessionID: s.ID, TokenHash: rt.TokenHash, ExpiresAt: rt.ExpiresAt}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(sm).Error; err != nil {
			return err
		}
		return tx.Create(tm).Error
	})
	s.CreatedAt, s.LastRefreshedAt = sm.CreatedAt, sm.LastRefreshedAt
	return mapErr(err)
}

// GetByRefreshToken finds a refresh token by its hash, with its session.
func (r *SessionRepository) GetByRefreshToken(ctx context.Context, hash []byte) (*domain.RefreshToken, *domain.Session, error) {
	db := r.db.WithContext(ctx)
	var tm refreshTokenModel
	if err := db.Where("token_hash = ?", hash).Take(&tm).Error; err != nil {
		return nil, nil, mapErr(err)
	}
	var sm sessionModel
	if err := db.Where("id = ?", tm.SessionID).Take(&sm).Error; err != nil {
		return nil, nil, mapErr(err)
	}
	return tm.toDomain(), sm.toDomain(), nil
}

// Rotate marks a refresh token used and stores its successor atomically.
// The conditional update makes concurrent refreshes with the same token
// race-safe: exactly one wins.
func (r *SessionRepository) Rotate(ctx context.Context, oldTokenID uuid.UUID, next *domain.RefreshToken) error {
	now := time.Now().UTC()
	return mapErr(r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&refreshTokenModel{}).Where("id = ? AND used_at IS NULL", oldTokenID).Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return domain.ErrInvalidToken
		}
		if err := tx.Create(&refreshTokenModel{ID: next.ID, SessionID: next.SessionID, TokenHash: next.TokenHash, ExpiresAt: next.ExpiresAt}).Error; err != nil {
			return err
		}
		return tx.Model(&sessionModel{}).Where("id = ?", next.SessionID).Update("last_refreshed_at", now).Error
	}))
}

// Revoke ends a session; its access and refresh tokens stop working.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&sessionModel{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).Update("revoked_at", time.Now().UTC()).Error
}

// RevokeAllForUser ends every session of a user, optionally keeping one.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID, keep *uuid.UUID) error {
	q := r.db.WithContext(ctx).Model(&sessionModel{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if keep != nil {
		q = q.Where("id <> ?", *keep)
	}
	return q.Update("revoked_at", time.Now().UTC()).Error
}

// Purge deletes sessions (cascading to tokens) and refresh tokens that
// expired or were revoked before t.
func (r *SessionRepository) Purge(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("expires_at < ? OR revoked_at < ?", before, before).Delete(&sessionModel{})
		if res.Error != nil {
			return res.Error
		}
		total += res.RowsAffected
		res = tx.Where("expires_at < ?", before).Delete(&refreshTokenModel{})
		total += res.RowsAffected
		return res.Error
	})
	return total, err
}
