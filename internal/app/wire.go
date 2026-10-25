//go:build wireinject

package app

import (
	"context"

	"github.com/google/wire"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/config"
)

// InitializeServer builds the full HTTP application.
func InitializeServer(ctx context.Context, cfg *config.Config, log *zap.Logger) (*Server, func(), error) {
	wire.Build(ConfigSet, RepositorySet, ServiceSet, HTTPSet, wire.Struct(new(Server), "*"))
	return nil, nil, nil
}

// InitializeTools builds the services used by CLI commands (seed, admin,
// maintenance) without the HTTP stack.
func InitializeTools(ctx context.Context, cfg *config.Config, log *zap.Logger) (*Tools, func(), error) {
	wire.Build(ConfigSet, RepositorySet, ServiceSet, wire.Struct(new(Tools), "*"))
	return nil, nil, nil
}
