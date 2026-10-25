// Package logger builds the application's zap logger.
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/MhmdRyhn/gate/internal/config"
)

// New returns a structured logger. JSON output (the default) is meant for
// log shippers; console output for local development. Sampling caps
// repeated identical messages so a log storm cannot overwhelm the pipeline.
func New(cfg config.LogConfig) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}

	zc := zap.NewProductionConfig()
	zc.Level = zap.NewAtomicLevelAt(level)
	zc.EncoderConfig.TimeKey = "time"
	zc.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zc.DisableStacktrace = true // stack traces are attached explicitly to panics
	if cfg.Format == "console" {
		zc.Encoding = "console"
		zc.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	return zc.Build()
}
