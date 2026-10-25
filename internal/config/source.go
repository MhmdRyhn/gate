package config

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Source provides configuration as flat key/value pairs.
//
// Implement it to add a new backend (Vault, etcd, GCP Secret Manager, ...).
// A source must return keys in canonical form (upper case, '_' separated, as
// produced by NormalizeKey) and should treat "no data" as an empty map, not
// an error, so optional layers can be stacked.
type Source interface {
	// Name identifies the source in error messages.
	Name() string
	// Load returns every key/value pair the source currently holds.
	Load(ctx context.Context) (map[string]string, error)
}

// NormalizeKey maps keys from any backend to the canonical form:
// "database-url", "database.url" and "DATABASE_URL" all become "DATABASE_URL".
func NormalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(k)
	return strings.ToUpper(k)
}

// ParseSource builds a Source from a CLI spec. Supported forms:
//
//	env                      process environment
//	env:PREFIX_              environment, only keys with PREFIX_ (stripped)
//	file:/path/.env          dotenv file (KEY=VALUE lines)
//	dir:/etc/rbac/secrets    one file per key: Kubernetes ConfigMap/Secret volumes, Docker secrets
//	consul:http://consul:8500/rbac-service   Consul KV prefix (token from CONSUL_HTTP_TOKEN)
//	http:http://localhost:2772/applications/a/environments/e/configurations/p
//	                         flat JSON object over HTTP(S): AWS AppConfig Agent, config servers
func ParseSource(spec string) (Source, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "env":
		return EnvSource{Prefix: arg}, nil
	case "file":
		if arg == "" {
			return nil, fmt.Errorf("config source %q: missing file path", spec)
		}
		return DotenvSource{Path: arg}, nil
	case "dir":
		if arg == "" {
			return nil, fmt.Errorf("config source %q: missing directory", spec)
		}
		return DirSource{Path: arg}, nil
	case "consul":
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("config source %q: expected consul:<scheme>://<host:port>/<prefix>", spec)
		}
		prefix := strings.Trim(u.Path, "/")
		u.Path = ""
		return &ConsulSource{Address: u.String(), Prefix: prefix, Token: os.Getenv("CONSUL_HTTP_TOKEN")}, nil
	case "http":
		u, err := url.Parse(arg)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("config source %q: expected http:<http(s) URL>", spec)
		}
		return &HTTPJSONSource{URL: arg}, nil
	default:
		return nil, fmt.Errorf("unknown config source %q (want env, file, dir, consul or http)", spec)
	}
}
