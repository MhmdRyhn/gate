// Package cli defines the rbac-service command line (cobra).
//
//	rbac-service serve                 run the HTTP API
//	rbac-service seed                  sync permissions, roles, public types
//	rbac-service admin create          create an admin (password via prompt/stdin)
//	rbac-service keys generate|public  manage JWT signing keys
//	rbac-service config print          show effective config (secrets redacted)
//	rbac-service maintenance purge-sessions
//	rbac-service healthcheck           container health probe
//	rbac-service version
//
// Global flag --config-source (repeatable) selects where configuration is
// read from; later sources override earlier ones.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/app"
	"github.com/MhmdRyhn/gate/internal/config"
	"github.com/MhmdRyhn/gate/internal/logger"
)

// globalFlags are shared by every command.
type globalFlags struct {
	configSources []string
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func newRootCmd() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           "rbac-service",
		Short:         "Authentication and role-based access control service",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringArrayVar(&g.configSources, "config-source", []string{"env"},
		"configuration source, repeatable; later wins.\n"+
			"env | env:PREFIX_ | file:PATH | dir:PATH | consul:URL/PREFIX | http:URL")

	root.AddCommand(
		newServeCmd(g),
		newSeedCmd(g),
		newAdminCmd(g),
		newKeysCmd(),
		newConfigCmd(g),
		newMaintenanceCmd(g),
		newHealthcheckCmd(),
		newVersionCmd(),
	)
	return root
}

// loadConfig reads configuration from the selected sources.
func (g *globalFlags) loadConfig(ctx context.Context) (*config.Config, error) {
	sources := make([]config.Source, 0, len(g.configSources))
	for _, spec := range g.configSources {
		s, err := config.ParseSource(spec)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return config.Load(ctx, sources...)
}

// bootstrap loads config and builds the logger.
func (g *globalFlags) bootstrap(ctx context.Context) (*config.Config, *zap.Logger, error) {
	cfg, err := g.loadConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	log, err := logger.New(cfg.Log)
	if err != nil {
		return nil, nil, err
	}
	return cfg, log, nil
}

// withTools runs fn with the CLI tool services and releases them after.
func (g *globalFlags) withTools(ctx context.Context, fn func(*app.Tools, *zap.Logger) error) error {
	cfg, log, err := g.bootstrap(ctx)
	if err != nil {
		return err
	}
	defer log.Sync() //nolint:errcheck
	tools, cleanup, err := app.InitializeTools(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(tools, log)
}
