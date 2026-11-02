package config

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/MhmdRyhn/gate/internal/configkit"
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
//	dir:/etc/gate/secrets    one file per key: Kubernetes ConfigMap/Secret volumes, Docker secrets
//	consul:http://consul:8500/gate   Consul KV prefix, one key per setting (token from CONSUL_HTTP_TOKEN)
//	http:http://localhost:2772/applications/a/environments/e/configurations/p
//	                         flat JSON object over HTTP(S): AWS AppConfig Agent, config servers
//
// Document sources (internal/configkit) take a comma-separated list of
// items, each a document in its own format, merged in order (later wins):
//
//	file:config.yaml,overrides.json,toml:local.conf
//	consul-doc:http://consul:8500/gate/base.yaml,json:gate/db      (token from CONSUL_HTTP_TOKEN)
//	aws-ssm:yaml:/gate/prod/base,json:/gate/prod/db                SSM Parameter Store parameters
//	aws-appconfig:yaml:gate/prod/main,json:gate/prod/flags         application/environment/profile
//	aws-secrets:json:gate/prod,toml:arn:aws:secretsmanager:...      secret names or ARNs
//
// An item is [json:|yaml:|toml:]<target>. Its format is the prefix if given,
// else the target's extension (.json, .yaml, .yml, .toml), else the format of
// the item before it, so "aws-ssm:yaml:/a,/b" reads both as YAML. Missing
// files are skipped, like a missing .env file. A single file: item without a
// document format is a dotenv file. The aws-* sources use the default AWS
// credential chain and region (instance role, shared config, ...).
func ParseSource(spec string) (Source, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "env":
		return EnvSource{Prefix: arg}, nil
	case "file":
		if arg == "" {
			return nil, fmt.Errorf("config source %q: missing file path", spec)
		}
		if !strings.Contains(arg, ",") && !hasFormatPrefix(arg) {
			if _, err := configkit.FormatFromPath(arg); err != nil {
				return DotenvSource{Path: arg}, nil
			}
		}
		return parseDocumentSource(spec, kind, arg)
	case "consul-doc", "aws-ssm", "aws-appconfig", "aws-secrets":
		return parseDocumentSource(spec, kind, arg)
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
		return nil, fmt.Errorf("unknown config source %q (want env, file, dir, consul, consul-doc, aws-ssm, aws-appconfig, aws-secrets or http)", spec)
	}
}

// docItem is one item of a document source list: a target and its format.
type docItem struct {
	target string
	format configkit.Format
}

// parseFormat recognises a format name (json, yaml, yml, toml).
func parseFormat(s string) (configkit.Format, bool) {
	switch strings.ToLower(s) {
	case "json":
		return configkit.JSON, true
	case "yaml", "yml":
		return configkit.YAML, true
	case "toml":
		return configkit.TOML, true
	}
	return "", false
}

func hasFormatPrefix(item string) bool {
	prefix, _, ok := strings.Cut(item, ":")
	_, isFormat := parseFormat(prefix)
	return ok && isFormat
}

// parseDocItems splits "[fmt:]target,[fmt:]target,..." and resolves each
// item's format: its prefix, else its extension, else the previous item's.
func parseDocItems(list string) ([]docItem, error) {
	var items []docItem
	var previous configkit.Format
	for _, raw := range strings.Split(list, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		item := docItem{target: raw}
		if prefix, rest, ok := strings.Cut(raw, ":"); ok {
			if f, isFormat := parseFormat(prefix); isFormat {
				item = docItem{target: rest, format: f}
			}
		}
		if item.target == "" {
			return nil, fmt.Errorf("item %q: missing target", raw)
		}
		if item.format == "" {
			if f, err := configkit.FormatFromPath(item.target); err == nil {
				item.format = f
			} else {
				item.format = previous
			}
		}
		if item.format == "" {
			return nil, fmt.Errorf("item %q: unknown format; prefix it with json:, yaml: or toml:", raw)
		}
		previous = item.format
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, errors.New("no items")
	}
	return items, nil
}

// parseDocumentSource builds a DocumentSource from a list of items; every
// kind shares the item grammar described on ParseSource.
func parseDocumentSource(spec, kind, arg string) (Source, error) {
	usage := map[string]string{
		"file":          "file:[fmt:]<path>[,[fmt:]<path>...]",
		"consul-doc":    "consul-doc:<scheme>://<host:port>/[fmt:]<key>[,[fmt:]<key>...]",
		"aws-ssm":       "aws-ssm:[fmt:]<name>[,[fmt:]<name>...]",
		"aws-appconfig": "aws-appconfig:[fmt:]<application>/<environment>/<profile>[,...]",
		"aws-secrets":   "aws-secrets:[fmt:]<secret name or ARN>[,...]",
	}[kind]
	invalid := func(err error) (Source, error) {
		return nil, fmt.Errorf("config source %q: %w (expected %s)", spec, err, usage)
	}

	list := arg
	var endpoint string
	if kind == "consul-doc" {
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" {
			return invalid(errors.New("invalid Consul address"))
		}
		list = strings.TrimPrefix(u.Path, "/")
		u.Path = ""
		endpoint = u.String()
	}
	items, err := parseDocItems(list)
	if err != nil {
		return invalid(err)
	}

	var sources []configkit.Source
	var params []configkit.SSMParameter
	for _, it := range items {
		switch kind {
		case "file":
			// A missing file yields no values, like a missing .env file.
			sources = append(sources, configkit.NewOptional(configkit.NewFileAs(it.target, it.format)))
		case "consul-doc":
			sources = append(sources, configkit.NewConsul(endpoint, strings.Trim(it.target, "/"), it.format))
		case "aws-ssm":
			params = append(params, configkit.SSMParameter{Name: it.target, Format: it.format})
		case "aws-appconfig":
			parts := strings.Split(it.target, "/")
			if len(parts) != 3 || slices.Contains(parts, "") {
				return invalid(fmt.Errorf("item %q: expected <application>/<environment>/<profile>", it.target))
			}
			sources = append(sources, configkit.NewAppConfig(parts[0], parts[1], parts[2], it.format))
		case "aws-secrets":
			sources = append(sources, configkit.NewSecretsManager(it.target, it.format))
		}
	}
	if len(params) > 0 {
		// One source, so the parameters are fetched in batched calls.
		sources = append(sources, configkit.NewSSMParameters(params...))
	}
	return DocumentSource{Sources: sources}, nil
}
