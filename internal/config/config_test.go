package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type mapSource map[string]string

func (m mapSource) Name() string                                    { return "map" }
func (m mapSource) Load(context.Context) (map[string]string, error) { return m, nil }

func newRequiredSource() mapSource {
	return mapSource{"DATABASE_URL": "postgres://u:p@h/db", "JWT_ISSUER": "https://auth.example.com", "JWT_SIGNING_KEY": "k"}
}

func TestLoadDefaultsAndPrecedence(t *testing.T) {
	cfg, err := Load(context.Background(), newRequiredSource(), mapSource{"HTTP_ADDR": ":9000", "HTTP_TRUSTED_PROXIES": "10.0.0.0/8,172.16.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9000" || cfg.Auth.AccessTokenTTL != 15*time.Minute || len(cfg.HTTP.TrustedProxies) != 2 {
		t.Errorf("unexpected config: %+v", cfg.HTTP)
	}
	if cfg.Database.URL.Value() != "postgres://u:p@h/db" {
		t.Error("secret value not decoded")
	}
}

func TestLoadValidation(t *testing.T) {
	if _, err := Load(context.Background(), mapSource{}); err == nil {
		t.Error("missing required keys accepted")
	}
	bad := newRequiredSource()
	bad["ACCESS_TOKEN_TTL"] = "2h"
	if _, err := Load(context.Background(), bad); err == nil {
		t.Error("long access token TTL accepted")
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("hunter2")
	b, _ := json.Marshal(struct{ S Secret }{s})
	for _, out := range []string{s.String(), fmt.Sprintf("%v %s %#v", s, s, s), string(b)} {
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret leaked: %s", out)
		}
	}
}

func TestEnvSourcePrefix(t *testing.T) {
	t.Setenv("GATETEST_HTTP_ADDR", ":1")
	kv, _ := EnvSource{Prefix: "GATETEST_"}.Load(context.Background())
	if kv["HTTP_ADDR"] != ":1" || len(kv) != 1 {
		t.Errorf("got %v", kv)
	}
}

func TestDirSourceKubernetesLayout(t *testing.T) {
	// Kubernetes mounts: key -> ..data/key symlink, plus hidden bookkeeping.
	dir := t.TempDir()
	data := filepath.Join(dir, "..data")
	os.Mkdir(data, 0o700)
	os.WriteFile(filepath.Join(data, "database-url"), []byte("postgres://x\n"), 0o600)
	os.Symlink(filepath.Join(data, "database-url"), filepath.Join(dir, "database-url"))

	kv, err := DirSource{Path: dir}.Load(context.Background())
	if err != nil || kv["DATABASE_URL"] != "postgres://x" || len(kv) != 1 {
		t.Errorf("got %v, %v", kv, err)
	}
	if kv, err := (DirSource{Path: filepath.Join(dir, "missing")}).Load(context.Background()); err != nil || len(kv) != 0 {
		t.Errorf("missing dir: %v, %v", kv, err)
	}
}

func TestParseDotenv(t *testing.T) {
	kv, err := parseDotenv(strings.NewReader("# c\nexport A=1\nB=\"two words\"\nc.d='x=y'\n\n"))
	if err != nil || kv["A"] != "1" || kv["B"] != "two words" || kv["C_D"] != "x=y" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestConsulSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/gate" || r.Header.Get("X-Consul-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		v := base64.StdEncoding.EncodeToString([]byte(":7000"))
		fmt.Fprintf(w, `[{"Key":"gate/","Value":null},{"Key":"gate/http_addr","Value":%q}]`, v)
	}))
	defer srv.Close()

	src, err := ParseSource("consul:" + srv.URL + "/gate")
	if err != nil {
		t.Fatal(err)
	}
	src.(*ConsulSource).Token = "tok"
	kv, err := src.Load(context.Background())
	if err != nil || kv["HTTP_ADDR"] != ":7000" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestHTTPJSONSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"HTTP_ADDR":":6000","DB_MAX_OPEN_CONNS":50,"PUBLIC_REGISTRATION_ENABLED":false,"HTTP_MAX_BODY_BYTES":1048576}`)
	}))
	defer srv.Close()

	src, _ := ParseSource("http:" + srv.URL)
	kv, err := src.Load(context.Background())
	if err != nil || kv["DB_MAX_OPEN_CONNS"] != "50" || kv["PUBLIC_REGISTRATION_ENABLED"] != "false" {
		t.Errorf("got %v, %v", kv, err)
	}
	// JSON numbers decode as float64; large ones must not become 1.048576e+06.
	if kv["HTTP_MAX_BODY_BYTES"] != "1048576" {
		t.Errorf("large number formatted as %q", kv["HTTP_MAX_BODY_BYTES"])
	}
}

func TestParseSourceErrors(t *testing.T) {
	for _, spec := range []string{"vault", "dir:", "file:", "consul:nope", "http:ftp://x",
		"consul-doc:nope", "consul-doc:http://consul:8500/", "consul-doc:http://consul:8500/gate/config.ini"} {
		if _, err := ParseSource(spec); err == nil {
			t.Errorf("%q accepted", spec)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentSourcesLayerWithEnv(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "config.yaml")
	writeFile(t, base, `
database:
  url: postgres://u:p@h/db
db_max_open_conns: 40
http:
  addr: ":9000"
  trusted_proxies: [10.0.0.0/8, 172.16.0.1]
jwt:
  issuer: https://auth.example.com
  signing_key: k
access_token_ttl: 10m
`)
	override := filepath.Join(dir, "override.json")
	writeFile(t, override, `{"http": {"max_body_bytes": 2097152}, "DB_MAX_OPEN_CONNS": 50}`)

	sources := []Source{}
	for _, spec := range []string{"file:" + base, "file:" + override, "file:" + filepath.Join(dir, "missing.yaml")} {
		s, err := ParseSource(spec)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, s)
	}
	cfg, err := Load(context.Background(), append(sources, mapSource{"HTTP_ADDR": ":9100"})...)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case cfg.Database.URL.Value() != "postgres://u:p@h/db":
		t.Error("nested database.url not mapped to DATABASE_URL")
	case cfg.Database.MaxOpenConns != 50:
		t.Errorf("later document should win: DB_MAX_OPEN_CONNS = %d", cfg.Database.MaxOpenConns)
	case cfg.HTTP.MaxBodyBytes != 2097152:
		t.Errorf("JSON number decoded as %d", cfg.HTTP.MaxBodyBytes)
	case len(cfg.HTTP.TrustedProxies) != 2:
		t.Errorf("YAML list not mapped: %v", cfg.HTTP.TrustedProxies)
	case cfg.HTTP.Addr != ":9100":
		t.Errorf("a later source should override the document: %s", cfg.HTTP.Addr)
	case cfg.Auth.AccessTokenTTL != 10*time.Minute:
		t.Errorf("duration not decoded: %s", cfg.Auth.AccessTokenTTL)
	}
}

func TestDocumentSourceRejectsUnknownKeys(t *testing.T) {
	// "auth" is a Go struct section, not a key prefix: this would be
	// AUTH_ACCESS_TOKEN_TTL, which no setting uses.
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, "auth:\n  access_token_ttl: 10m\n")
	src, _ := ParseSource("file:" + path)
	_, err := Load(context.Background(), newRequiredSource(), src)
	if err == nil || !strings.Contains(err.Error(), "AUTH_ACCESS_TOKEN_TTL") {
		t.Errorf("unknown key accepted: %v", err)
	}
	// The environment is not strict: unrelated variables are normal there.
	if _, err := Load(context.Background(), newRequiredSource(), mapSource{"PATH": "/bin"}); err != nil {
		t.Errorf("unrelated env var rejected: %v", err)
	}
}

func TestDocumentSourceRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, "database:\n  url: a\nDATABASE_URL: b\n")
	src, _ := ParseSource("file:" + path)
	if _, err := src.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("duplicate key accepted: %v", err)
	}
}

func TestDocumentSourceInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, "{not json")
	src, _ := ParseSource("file:" + path)
	if _, err := src.Load(context.Background()); err == nil {
		t.Error("invalid JSON accepted")
	}
}

func TestConsulDocumentSource(t *testing.T) {
	// A Consul KV endpoint returning one key that holds a YAML document.
	doc := base64.StdEncoding.EncodeToString([]byte("http:\n  addr: \":7100\"\njwt:\n  audience: api\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/gate/config.yaml" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"Key":"gate/config.yaml","Value":%q,"ModifyIndex":1}]`, doc)
	}))
	defer srv.Close()

	src, err := ParseSource("consul-doc:" + srv.URL + "/gate/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := src.Load(context.Background())
	if err != nil || kv["HTTP_ADDR"] != ":7100" || kv["JWT_AUDIENCE"] != "api" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestAWSSourceSpecs(t *testing.T) {
	for spec, want := range map[string]string{
		"aws-ssm:yaml:/gate/prod/base, /gate/prod/db": "aws ssm /gate/prod/base,/gate/prod/db",
		"aws-ssm:yml:/gate/prod/base":                 "aws ssm /gate/prod/base",
		"aws-appconfig:toml:gate/prod/main":           "aws appconfig gate/prod/main",
		"aws-secrets:json:gate/prod":                  "aws secrets manager gate/prod",
		// ARNs contain ':'; everything after the format is the secret ID.
		"aws-secrets:json:arn:aws:secretsmanager:eu-west-1:123456789012:secret:gate/prod-AbCdEf": "aws secrets manager arn:aws:secretsmanager:eu-west-1:123456789012:secret:gate/prod-AbCdEf",
	} {
		src, err := ParseSource(spec)
		if err != nil {
			t.Errorf("%s: %v", spec, err)
			continue
		}
		if src.Name() != want {
			t.Errorf("%s: Name() = %q, want %q", spec, src.Name(), want)
		}
	}
	for _, bad := range []string{
		"aws-ssm:yaml:", "aws-ssm:ini:/a", "aws-ssm:/a",
		"aws-appconfig:yaml:gate/prod", "aws-appconfig:yaml:gate//main", "aws-appconfig:yaml:a/b/c/d",
		"aws-secrets:json:", "aws-secrets:gate/prod",
	} {
		if _, err := ParseSource(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTOMLDocumentSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, "access_token_ttl = \"5m\"\n\n[http]\naddr = \":9200\"\ntrusted_proxies = [\"10.0.0.0/8\"]\n")
	src, err := ParseSource("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(context.Background(), newRequiredSource(), src)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9200" || cfg.Auth.AccessTokenTTL != 5*time.Minute || len(cfg.HTTP.TrustedProxies) != 1 {
		t.Errorf("unexpected config: %s %s %v", cfg.HTTP.Addr, cfg.Auth.AccessTokenTTL, cfg.HTTP.TrustedProxies)
	}
}

func TestParseDocItems(t *testing.T) {
	items, err := parseDocItems("yaml:/a, /b.json, /c, toml:/d, arn:aws:secretsmanager:x:1:secret:s, json:arn:aws:secretsmanager:x:1:secret:t")
	if err != nil {
		t.Fatal(err)
	}
	want := []docItem{
		{"/a", "yaml"},
		{"/b.json", "json"}, // extension
		{"/c", "json"},      // inherited from the previous item
		{"/d", "toml"},      // prefix
		{"arn:aws:secretsmanager:x:1:secret:s", "toml"}, // "arn" is not a format
		{"arn:aws:secretsmanager:x:1:secret:t", "json"},
	}
	if !slices.Equal(items, want) {
		t.Errorf("got  %v\nwant %v", items, want)
	}
	for _, bad := range []string{"", ",", "/no-format", "yaml:", "ini:/a"} {
		if _, err := parseDocItems(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMixedFormatFileList(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "base.yaml"), "http:\n  addr: \":9000\"\ndb_max_open_conns: 10\n")
	writeFile(t, filepath.Join(dir, "db.json"), `{"database": {"url": "postgres://u:p@h/db"}, "db_max_open_conns": 20}`)
	writeFile(t, filepath.Join(dir, "local.conf"), "db_max_open_conns = 30\n") // no extension: format from the prefix
	spec := "file:" + filepath.Join(dir, "base.yaml") + "," + filepath.Join(dir, "missing.json") + "," +
		filepath.Join(dir, "db.json") + ",toml:" + filepath.Join(dir, "local.conf")
	src, err := ParseSource(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(context.Background(), mapSource{"JWT_ISSUER": "https://a", "JWT_SIGNING_KEY": "k"}, src)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9000" || cfg.Database.URL.Value() != "postgres://u:p@h/db" || cfg.Database.MaxOpenConns != 30 {
		t.Errorf("yaml+json+toml not merged in order: addr=%s max=%d", cfg.HTTP.Addr, cfg.Database.MaxOpenConns)
	}
	// A single file without a document format is still a dotenv file.
	if src, _ := ParseSource("file:" + filepath.Join(dir, ".env")); fmt.Sprintf("%T", src) != "config.DotenvSource" {
		t.Errorf("single .env file parsed as %T", src)
	}
}

func TestMixedFormatAWSSpecs(t *testing.T) {
	for spec, want := range map[string]string{
		"aws-ssm:yaml:/gate/prod/base,json:/gate/prod/db,toml:/gate/prod/local": "aws ssm /gate/prod/base,/gate/prod/db,/gate/prod/local",
		"aws-appconfig:yaml:gate/prod/main,json:gate/prod/flags":                "aws appconfig gate/prod/main + aws appconfig gate/prod/flags",
		"aws-secrets:json:gate/prod,toml:gate/extra":                            "aws secrets manager gate/prod + aws secrets manager gate/extra",
	} {
		src, err := ParseSource(spec)
		if err != nil {
			t.Errorf("%s: %v", spec, err)
			continue
		}
		if src.Name() != want {
			t.Errorf("%s: Name() = %q, want %q", spec, src.Name(), want)
		}
	}
	if _, err := ParseSource("aws-appconfig:yaml:gate/prod/main,json:gate/prod"); err == nil {
		t.Error("malformed second AppConfig item accepted")
	}
}

func TestConsulDocumentList(t *testing.T) {
	docs := map[string]string{
		"/v1/kv/gate/base.yaml": "http:\n  addr: \":7100\"\n",
		"/v1/kv/gate/db":        `{"jwt": {"audience": "api"}, "http": {"addr": ":7200"}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := docs[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		key := strings.TrimPrefix(r.URL.Path, "/v1/kv/")
		fmt.Fprintf(w, `[{"Key":%q,"Value":%q,"ModifyIndex":1}]`, key, base64.StdEncoding.EncodeToString([]byte(doc)))
	}))
	defer srv.Close()

	src, err := ParseSource("consul-doc:" + srv.URL + "/gate/base.yaml,json:gate/db")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := src.Load(context.Background())
	if err != nil || kv["HTTP_ADDR"] != ":7200" || kv["JWT_AUDIENCE"] != "api" {
		t.Errorf("got %v, %v", kv, err)
	}
}
