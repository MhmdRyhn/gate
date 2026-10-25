package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/term"

	"github.com/MhmdRyhn/gate/internal/app"
	"github.com/MhmdRyhn/gate/internal/auth"
	"github.com/MhmdRyhn/gate/internal/version"
)

func newServeCmd(g *globalFlags) *cobra.Command {
	var syncRBAC bool
	var purgeEvery time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP API",
		Long: "Run the HTTP API. The database schema must already be migrated (see /migrations).\n" +
			"By default the permission/role/public-type registry is synced on start.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, log, err := g.bootstrap(ctx)
			if err != nil {
				return err
			}
			defer log.Sync() //nolint:errcheck
			log.Info("starting", zap.String("version", version.Version), zap.String("commit", version.Commit))

			srv, cleanup, err := app.InitializeServer(ctx, cfg, log)
			if err != nil {
				return err
			}
			defer cleanup()
			return srv.Run(ctx, syncRBAC, purgeEvery)
		},
	}
	cmd.Flags().BoolVar(&syncRBAC, "sync-rbac", true, "sync permissions, default roles and public types into the database on start")
	cmd.Flags().DurationVar(&purgeEvery, "purge-interval", time.Hour, "how often to delete ended sessions (0 disables)")
	return cmd
}

func newSeedCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "seed",
		Short: "Sync permissions, default roles and public user types into the database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return g.withTools(cmd.Context(), func(t *app.Tools, _ *zap.Logger) error {
				return t.Seeder.Sync(cmd.Context())
			})
		},
	}
}

func newAdminCmd(g *globalFlags) *cobra.Command {
	admin := &cobra.Command{Use: "admin", Short: "Administrative account tasks"}
	var email, phone, name string
	var passwordStdin bool
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an internal user with the admin role",
		Long: "Create an internal user with the admin role. The password is read from an\n" +
			"interactive prompt, or from stdin with --password-stdin; it is never a flag,\n" +
			"so it cannot leak through shell history or the process list.",
		Example: "  rbac-service admin create --email you@example.com\n" +
			"  printf '%s' \"$PW\" | rbac-service admin create --phone +8801700000000 --password-stdin",
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := readPassword(cmd, passwordStdin)
			if err != nil {
				return err
			}
			return g.withTools(cmd.Context(), func(t *app.Tools, _ *zap.Logger) error {
				if err := t.Seeder.Sync(cmd.Context()); err != nil {
					return err
				}
				u, err := t.Seeder.CreateAdmin(cmd.Context(), email, phone, name, password)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "admin created: %s\n", u.ID)
				return nil
			})
		},
	}
	create.Flags().StringVar(&email, "email", "", "admin email")
	create.Flags().StringVar(&phone, "phone", "", "admin phone (E.164)")
	create.Flags().StringVar(&name, "name", "Administrator", "full name")
	create.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	create.MarkFlagsOneRequired("email", "phone")
	admin.AddCommand(create)
	return admin
}

func readPassword(cmd *cobra.Command, fromStdin bool) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4096))
		return strings.TrimRight(string(b), "\r\n"), err
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal: use --password-stdin")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Repeat password: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passwords do not match")
	}
	return string(p1), nil
}

func newKeysCmd() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Manage JWT signing keys"}
	var kind string
	var bits int
	gen := &cobra.Command{
		Use:   "generate",
		Short: "Generate a PKCS#8 private signing key (PEM on stdout, key ID on stderr)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pemText, kid, err := auth.GenerateKey(kind, bits)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), pemText)
			fmt.Fprintf(cmd.ErrOrStderr(), "kid: %s\n", kid)
			return nil
		},
	}
	gen.Flags().StringVar(&kind, "type", "ed25519", "key type: ed25519 (EdDSA) or rsa (RS256)")
	gen.Flags().IntVar(&bits, "bits", 3072, "RSA key size")

	pub := &cobra.Command{
		Use:   "public",
		Short: "Print the public key of a private key read from stdin (for JWT_VERIFICATION_KEYS)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := io.ReadAll(bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 64<<10)))
			if err != nil {
				return err
			}
			out, err := auth.PublicKeyPEM(string(in))
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil
		},
	}
	keys.AddCommand(gen, pub)
	return keys
}

func newConfigCmd(g *globalFlags) *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Inspect configuration"}
	c.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Validate and print the effective configuration (secrets redacted)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.loadConfig(cmd.Context())
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	})
	return c
}

func newMaintenanceCmd(g *globalFlags) *cobra.Command {
	m := &cobra.Command{Use: "maintenance", Short: "Periodic maintenance tasks (run from cron / Kubernetes CronJob)"}
	var olderThan time.Duration
	purge := &cobra.Command{
		Use:   "purge-sessions",
		Short: "Delete sessions and refresh tokens that ended before now minus --older-than",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return g.withTools(cmd.Context(), func(t *app.Tools, log *zap.Logger) error {
				n, err := t.Auth.PurgeSessions(cmd.Context(), time.Now().Add(-olderThan))
				if err == nil {
					log.Info("purged ended sessions", zap.Int64("rows", n))
				}
				return err
			})
		},
	}
	purge.Flags().DurationVar(&olderThan, "older-than", 24*time.Hour, "grace period after a session ended")
	m.AddCommand(purge)
	return m
}

func newHealthcheckCmd() *cobra.Command {
	var url string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe the local /healthz endpoint (exit 0 when healthy); for container HEALTHCHECK",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if url == "" {
				port := "8080"
				if _, p, err := net.SplitHostPort(os.Getenv("HTTP_ADDR")); err == nil && p != "" {
					port = p
				}
				url = "http://127.0.0.1:" + port + "/healthz"
			}
			client := http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "health URL (default http://127.0.0.1:$HTTP_ADDR port/healthz)")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "rbac-service %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
		},
	}
}
