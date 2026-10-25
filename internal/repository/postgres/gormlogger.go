package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/MhmdRyhn/gate/internal/requestctx"
)

// gormLogger routes gorm's logs to zap.
//
// Security: it implements gorm's ParamsFilter so SQL is logged with
// placeholders only. Bound values (password hashes, token hashes, emails,
// phone numbers) never reach the logs.
type gormLogger struct {
	log   *zap.Logger
	slow  time.Duration
	level gormlogger.LogLevel
}

func newGormLogger(log *zap.Logger, slow time.Duration) gormlogger.Interface {
	return &gormLogger{log: log.Named("gorm"), slow: slow, level: gormlogger.Warn}
}

func (l *gormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	c := *l
	c.level = level
	return &c
}

func (l *gormLogger) Info(ctx context.Context, msg string, args ...any) {
	if l.level >= gormlogger.Info {
		l.with(ctx).Info(fmt.Sprintf(msg, args...))
	}
}

func (l *gormLogger) Warn(ctx context.Context, msg string, args ...any) {
	if l.level >= gormlogger.Warn {
		l.with(ctx).Warn(fmt.Sprintf(msg, args...))
	}
}

func (l *gormLogger) Error(ctx context.Context, msg string, args ...any) {
	if l.level >= gormlogger.Error {
		l.with(ctx).Error(fmt.Sprintf(msg, args...))
	}
}

// Trace logs failed queries as errors, slow queries as warnings and, at
// debug level, every query.
func (l *gormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	elapsed := time.Since(begin)
	log := l.with(ctx)
	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound) && l.level >= gormlogger.Error:
		sql, rows := fc()
		log.Error("query failed", zap.Error(err), zap.String("sql", sql), zap.Int64("rows", rows), zap.Duration("elapsed", elapsed))
	case elapsed > l.slow && l.level >= gormlogger.Warn:
		sql, rows := fc()
		log.Warn("slow query", zap.String("sql", sql), zap.Int64("rows", rows), zap.Duration("elapsed", elapsed))
	case log.Core().Enabled(zap.DebugLevel):
		sql, rows := fc()
		log.Debug("query", zap.String("sql", sql), zap.Int64("rows", rows), zap.Duration("elapsed", elapsed))
	}
}

// ParamsFilter drops bound parameters from logged SQL.
func (l *gormLogger) ParamsFilter(_ context.Context, sql string, _ ...any) (string, []any) {
	return sql, nil
}

func (l *gormLogger) with(ctx context.Context) *zap.Logger {
	if id := requestctx.From(ctx).RequestID; id != "" {
		return l.log.With(zap.String("request_id", id))
	}
	return l.log
}
