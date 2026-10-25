package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// effectiveRoleIDs selects the roles that apply to user @uid: roles assigned
// directly (internal users) plus roles granted by their public types.
const effectiveRoleIDs = `
	SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = @uid
	UNION
	SELECT t.role_id FROM user_public_types upt
	JOIN public_user_types t ON t.name = upt.type_name
	WHERE upt.user_id = @uid AND t.role_id IS NOT NULL`

// UserRepository implements repository.UserRepository.
type UserRepository struct{ db *gorm.DB }

var _ repository.UserRepository = (*UserRepository)(nil)

// NewUserRepository returns a gorm-backed user repository.
func NewUserRepository(db *gorm.DB) *UserRepository { return &UserRepository{db: db} }

// Create inserts the user with its roles, public types and SSO identity in
// one transaction.
func (r *UserRepository) Create(ctx context.Context, u *domain.User, opts repository.CreateUserOptions) error {
	m := toUserModel(u)
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("PublicTypes").Create(m).Error; err != nil {
			return err
		}
		for _, id := range opts.RoleIDs {
			if err := tx.Create(&userRoleModel{UserID: m.ID, RoleID: id}).Error; err != nil {
				return err
			}
		}
		for _, t := range opts.PublicTypes {
			if err := tx.Create(&userPublicTypeModel{UserID: m.ID, TypeName: t}).Error; err != nil {
				return err
			}
		}
		if id := opts.Identity; id != nil {
			id.UserID = m.ID
			return tx.Create(&userIdentityModel{ID: id.ID, UserID: id.UserID, Provider: id.Provider, Subject: id.Subject, Email: id.Email}).Error
		}
		return nil
	})
	if err != nil {
		return mapErr(err)
	}
	u.CreatedAt, u.UpdatedAt, u.PublicTypes = m.CreatedAt, m.UpdatedAt, opts.PublicTypes
	return nil
}

func (r *UserRepository) get(ctx context.Context, query string, arg any) (*domain.User, error) {
	var m userModel
	if err := r.db.WithContext(ctx).Preload("PublicTypes").Where(query, arg).Take(&m).Error; err != nil {
		return nil, mapErr(err)
	}
	return m.toDomain(), nil
}

// GetByID returns a user with its public types.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.get(ctx, "id = ?", id)
}

// GetByEmail looks a user up by normalised email.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.get(ctx, "email = ?", email)
}

// GetByPhone looks a user up by E.164 phone number.
func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	return r.get(ctx, "phone = ?", phone)
}

// List returns users ordered by creation time.
func (r *UserRepository) List(ctx context.Context, f domain.UserFilter) ([]domain.User, error) {
	q := r.db.WithContext(ctx).Model(&userModel{}).Preload("PublicTypes")
	if f.Kind != nil {
		q = q.Where("kind = ?", string(*f.Kind))
	}
	if f.PublicType != nil {
		q = q.Where("id IN (?)", r.db.Model(&userPublicTypeModel{}).Select("user_id").Where("type_name = ?", *f.PublicType))
	}
	var ms []userModel
	if err := q.Order("created_at, id").Limit(f.Limit).Offset(f.Offset).Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]domain.User, len(ms))
	for i := range ms {
		out[i] = *ms[i].toDomain()
	}
	return out, nil
}

// Count returns the total number of users.
func (r *UserRepository) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&userModel{}).Count(&n).Error
	return n, err
}

// Update applies a partial update and returns the updated user.
func (r *UserRepository) Update(ctx context.Context, id uuid.UUID, patch domain.UserPatch) (*domain.User, error) {
	changes := map[string]any{"updated_at": time.Now().UTC()}
	if patch.FullName != nil {
		changes["full_name"] = *patch.FullName
	}
	if patch.Status != nil {
		changes["status"] = string(*patch.Status)
	}
	res := r.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", id).Updates(changes)
	if res.Error != nil {
		return nil, mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, domain.ErrNotFound
	}
	return r.GetByID(ctx, id)
}

// UpdatePassword stores a new password hash.
func (r *UserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, hash string) error {
	res := r.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", id).
		Updates(map[string]any{"password_hash": hash, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// TouchLastLogin records a successful sign-in.
func (r *UserRepository) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", id).Update("last_login_at", time.Now().UTC()).Error
}

// SetRoles replaces an internal user's roles atomically.
func (r *UserRepository) SetRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return mapErr(r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&userRoleModel{}).Error; err != nil {
			return err
		}
		for _, id := range roleIDs {
			if err := tx.Create(&userRoleModel{UserID: userID, RoleID: id}).Error; err != nil {
				return err
			}
		}
		return nil
	}))
}

// SetPublicTypes replaces a public user's types atomically.
func (r *UserRepository) SetPublicTypes(ctx context.Context, userID uuid.UUID, types []string) error {
	return mapErr(r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&userPublicTypeModel{}).Error; err != nil {
			return err
		}
		for _, t := range types {
			if err := tx.Create(&userPublicTypeModel{UserID: userID, TypeName: t}).Error; err != nil {
				return err
			}
		}
		return nil
	}))
}

// EffectiveRoles returns assigned roles plus roles granted via public types.
func (r *UserRepository) EffectiveRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	var ms []roleModel
	err := r.db.WithContext(ctx).Preload("Permissions").
		Where("id IN ("+effectiveRoleIDs+")", sql.Named("uid", userID)).
		Order("name").Find(&ms).Error
	if err != nil {
		return nil, err
	}
	return rolesToDomain(ms), nil
}

// GetPrincipal resolves the request principal: the user must be active and
// the session unrevoked and unexpired. This runs on every authenticated
// request and is served by primary-key and indexed lookups.
func (r *UserRepository) GetPrincipal(ctx context.Context, userID, sessionID uuid.UUID) (*domain.Principal, error) {
	db := r.db.WithContext(ctx)
	var row struct{ Kind, Status string }
	res := db.Raw(`SELECT u.kind, u.status FROM users u
		JOIN sessions s ON s.user_id = u.id
		WHERE u.id = ? AND s.id = ? AND s.revoked_at IS NULL AND s.expires_at > now()`,
		userID, sessionID).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, domain.ErrNotFound
	}
	if domain.UserStatus(row.Status) != domain.UserStatusActive {
		return nil, domain.ErrUserDisabled
	}

	var codes []string
	if err := db.Raw(`SELECT DISTINCT permission_code FROM role_permissions WHERE role_id IN (`+effectiveRoleIDs+`)`,
		sql.Named("uid", userID)).Scan(&codes).Error; err != nil {
		return nil, err
	}
	var types []string
	if err := db.Model(&userPublicTypeModel{}).Where("user_id = ?", userID).Order("type_name").Pluck("type_name", &types).Error; err != nil {
		return nil, err
	}

	p := &domain.Principal{UserID: userID, SessionID: sessionID, Kind: domain.UserKind(row.Kind), PublicTypes: types, Permissions: domain.PermissionSet{}}
	for _, c := range codes {
		p.Permissions[domain.Permission(c)] = struct{}{}
	}
	return p, nil
}
