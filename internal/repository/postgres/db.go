// Package postgres implements the repository interfaces with gorm on
// PostgreSQL. The schema itself is managed outside the application (see
// /migrations); this package never runs DDL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/domain"
)

// Open connects to PostgreSQL, configures the pool and waits (with
// exponential backoff, up to cfg.ConnectTimeout) for the database to become
// reachable, so the service tolerates starting before its database.
// The returned cleanup closes the pool.
func Open(ctx context.Context, cfg config.DatabaseConfig, log *zap.Logger) (*gorm.DB, func(), error) {
	db, err := gorm.Open(postgres.Open(cfg.URL.Value()), &gorm.Config{
		Logger:                 newGormLogger(log, cfg.SlowQueryThreshold),
		TranslateError:         true, // unique/FK violations -> gorm.ErrDuplicatedKey / ErrForeignKeyViolated
		SkipDefaultTransaction: true, // explicit transactions only, where atomicity matters
		DisableAutomaticPing:   true, // we ping with retry below
		NowFunc:                func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, err
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	cleanup := func() { _ = sqlDB.Close() }

	deadline, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	for wait := 500 * time.Millisecond; ; wait = min(wait*2, 10*time.Second) {
		pingCtx, cancelPing := context.WithTimeout(deadline, 5*time.Second)
		err = sqlDB.PingContext(pingCtx)
		cancelPing()
		if err == nil {
			return db, cleanup, nil
		}
		log.Warn("database not reachable, retrying", zap.Error(err), zap.Duration("retry_in", wait))
		select {
		case <-deadline.Done():
			cleanup()
			return nil, nil, fmt.Errorf("database not reachable within %s: %w", cfg.ConnectTimeout, err)
		case <-time.After(wait):
		}
	}
}

// Health implements repository.HealthChecker.
type Health struct{ db *gorm.DB }

// NewHealth returns a database health checker.
func NewHealth(db *gorm.DB) *Health { return &Health{db: db} }

// Ping checks connectivity.
func (h *Health) Ping(ctx context.Context) error {
	sqlDB, err := h.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// mapErr translates gorm errors into domain errors.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return domain.ErrNotFound
	case errors.Is(err, gorm.ErrDuplicatedKey):
		return fmt.Errorf("%w: already exists", domain.ErrConflict)
	case errors.Is(err, gorm.ErrForeignKeyViolated):
		return fmt.Errorf("%w: still referenced or references a missing record", domain.ErrConflict)
	}
	return err
}
