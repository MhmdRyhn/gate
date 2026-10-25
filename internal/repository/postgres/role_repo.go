package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/repository"
)

// RoleRepository implements repository.RoleRepository.
type RoleRepository struct{ db *gorm.DB }

var _ repository.RoleRepository = (*RoleRepository)(nil)

// NewRoleRepository returns a gorm-backed role repository.
func NewRoleRepository(db *gorm.DB) *RoleRepository { return &RoleRepository{db: db} }

func rolesToDomain(ms []roleModel) []domain.Role {
	out := make([]domain.Role, len(ms))
	for i := range ms {
		out[i] = ms[i].toDomain()
	}
	return out
}

func (r *RoleRepository) query(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Preload("Permissions", func(db *gorm.DB) *gorm.DB {
		return db.Order("permission_code")
	})
}

// GetByID returns a role with its permissions.
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	var m roleModel
	if err := r.query(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		return nil, mapErr(err)
	}
	d := m.toDomain()
	return &d, nil
}

// GetByName returns a role by its unique name.
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*domain.Role, error) {
	var m roleModel
	if err := r.query(ctx).Where("name = ?", name).Take(&m).Error; err != nil {
		return nil, mapErr(err)
	}
	d := m.toDomain()
	return &d, nil
}

// GetByIDs returns the roles that exist among ids.
func (r *RoleRepository) GetByIDs(ctx context.Context, ids []uuid.UUID) ([]domain.Role, error) {
	if len(ids) == 0 {
		return []domain.Role{}, nil
	}
	var ms []roleModel
	if err := r.query(ctx).Where("id IN ?", ids).Order("name").Find(&ms).Error; err != nil {
		return nil, err
	}
	return rolesToDomain(ms), nil
}

// List returns every role ordered by name.
func (r *RoleRepository) List(ctx context.Context) ([]domain.Role, error) {
	var ms []roleModel
	if err := r.query(ctx).Order("name").Find(&ms).Error; err != nil {
		return nil, err
	}
	return rolesToDomain(ms), nil
}

// Create inserts a role and its permissions atomically.
func (r *RoleRepository) Create(ctx context.Context, role *domain.Role) error {
	m := &roleModel{ID: role.ID, Name: role.Name, Description: role.Description, Audience: string(role.Audience), IsSystem: role.IsSystem}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Permissions").Create(m).Error; err != nil {
			return err
		}
		return replacePermissions(tx, role.ID, role.Permissions)
	})
	role.CreatedAt, role.UpdatedAt = m.CreatedAt, m.UpdatedAt
	return mapErr(err)
}

// Update saves name, description and permissions atomically.
func (r *RoleRepository) Update(ctx context.Context, role *domain.Role) error {
	return mapErr(r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&roleModel{}).Where("id = ?", role.ID).Updates(map[string]any{
			"name": role.Name, "description": role.Description, "updated_at": time.Now().UTC(),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return replacePermissions(tx, role.ID, role.Permissions)
	}))
}

// Delete removes a role. It fails with ErrConflict while users hold it.
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&roleModel{})
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func replacePermissions(tx *gorm.DB, roleID uuid.UUID, perms []domain.Permission) error {
	if err := tx.Where("role_id = ?", roleID).Delete(&rolePermissionModel{}).Error; err != nil {
		return err
	}
	if len(perms) == 0 {
		return nil
	}
	rows := make([]rolePermissionModel, len(perms))
	for i, p := range perms {
		rows[i] = rolePermissionModel{RoleID: roleID, PermissionCode: string(p)}
	}
	return tx.Create(&rows).Error
}

// SyncPermissions upserts defs and deletes permissions no longer defined.
func (r *RoleRepository) SyncPermissions(ctx context.Context, defs []domain.PermissionDef) error {
	if len(defs) == 0 {
		return errors.New("refusing to sync an empty permission registry")
	}
	rows := make([]permissionModel, len(defs))
	codes := make([]string, len(defs))
	for i, d := range defs {
		rows[i] = permissionModel{Code: string(d.Code), Description: d.Description}
		codes[i] = string(d.Code)
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"description"}),
		}).Create(&rows).Error
		if err != nil {
			return err
		}
		return tx.Where("code NOT IN ?", codes).Delete(&permissionModel{}).Error
	})
}

// SeedRole creates the role if missing, or overwrites it when requested.
func (r *RoleRepository) SeedRole(ctx context.Context, role *domain.Role, overwrite bool) error {
	return mapErr(r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing roleModel
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("name = ?", role.Name).Take(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			m := &roleModel{ID: role.ID, Name: role.Name, Description: role.Description, Audience: string(role.Audience), IsSystem: role.IsSystem}
			if err := tx.Omit("Permissions").Create(m).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		case !overwrite:
			role.ID = existing.ID
			return nil
		default:
			role.ID = existing.ID
			if err := tx.Model(&existing).Updates(map[string]any{
				"description": role.Description, "audience": string(role.Audience),
				"is_system": role.IsSystem, "updated_at": time.Now().UTC(),
			}).Error; err != nil {
				return err
			}
		}
		return replacePermissions(tx, role.ID, role.Permissions)
	}))
}

// SyncPublicUserTypes upserts defs and removes types no longer defined.
func (r *RoleRepository) SyncPublicUserTypes(ctx context.Context, defs []domain.PublicUserType) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		names := make([]string, 0, len(defs))
		for _, d := range defs {
			names = append(names, d.Name)
			row := publicUserTypeModel{Name: d.Name, Description: d.Description, SelfRegistration: d.SelfRegistration}
			if d.Role != "" {
				var role roleModel
				if err := tx.Where("name = ? AND audience = ?", d.Role, string(domain.UserKindPublic)).Take(&role).Error; err != nil {
					return fmt.Errorf("public type %q: public role %q: %w", d.Name, d.Role, err)
				}
				row.RoleID = &role.ID
			}
			err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "name"}},
				DoUpdates: clause.AssignmentColumns([]string{"description", "role_id", "self_registration"}),
			}).Create(&row).Error
			if err != nil {
				return err
			}
		}
		q := tx.Model(&publicUserTypeModel{})
		if len(names) > 0 {
			q = q.Where("name NOT IN ?", names)
		} else {
			q = q.Where("true")
		}
		if err := q.Delete(&publicUserTypeModel{}).Error; err != nil {
			return fmt.Errorf("remove obsolete public user types (are they still held by users?): %w", err)
		}
		return nil
	})
}
