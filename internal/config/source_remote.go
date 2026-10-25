package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// remoteTimeout bounds every remote config fetch so startup cannot hang.
const remoteTimeout = 10 * time.Second

func defaultHTTPClient() *http.Client { return &http.Client{Timeout: remoteTimeout} }

// ConsulSource reads all keys under Prefix from Consul's KV store over its
// HTTP API (no SDK needed). "rbac-service/DATABASE_URL" becomes
// "DATABASE_URL"; nested folders are flattened with "_".
type ConsulSource struct {
	Address string // e.g. "https://consul.service:8501"
	Prefix  string // e.g. "rbac-service"
	Token   string // ACL token; sent as X-Consul-Token
	Client  *http.Client
}

func (s *ConsulSource) Name() string { return "consul:" + s.Prefix }

func (s *ConsulSource) Load(ctx context.Context) (map[string]string, error) {
	u := strings.TrimRight(s.Address, "/") + "/v1/kv/" + strings.Trim(s.Prefix, "/") + "?recurse=true"
	body, status, err := fetch(ctx, s.client(), u, map[string]string{"X-Consul-Token": s.Token})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound { // prefix has no keys yet
		return map[string]string{}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("consul returned HTTP %d", status)
	}

	var entries []struct {
		Key   string
		Value *string // base64; null for folders
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode consul response: %w", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.Value == nil {
			continue
		}
		v, err := base64.StdEncoding.DecodeString(*e.Value)
		if err != nil {
			return nil, fmt.Errorf("consul key %s: %w", e.Key, err)
		}
		k := strings.TrimPrefix(strings.TrimPrefix(e.Key, s.Prefix), "/")
		if k != "" {
			out[NormalizeKey(k)] = string(v)
		}
	}
	return out, nil
}

func (s *ConsulSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultHTTPClient()
}

// HTTPJSONSource fetches a flat JSON object ({"KEY": "value", ...}) from a
// URL. It works with the AWS AppConfig Agent (sidecar/Lambda extension at
// http://localhost:2772/applications/{app}/environments/{env}/configurations/{profile}),
// which handles AWS auth and caching, and with any config server that can
// serve a JSON document. Numbers and booleans are converted to strings.
type HTTPJSONSource struct {
	URL     string
	Headers map[string]string
	Client  *http.Client
}

func (s *HTTPJSONSource) Name() string { return "http:" + s.URL }

func (s *HTTPJSONSource) Load(ctx context.Context) (map[string]string, error) {
	client := s.Client
	if client == nil {
		client = defaultHTTPClient()
	}
	body, status, err := fetch(ctx, client, s.URL, s.Headers)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("expected a flat JSON object: %w", err)
	}
	out := make(map[string]string, len(doc))
	for k, v := range doc {
		switch v := v.(type) {
		case string:
			out[NormalizeKey(k)] = v
		case float64, bool:
			out[NormalizeKey(k)] = fmt.Sprint(v)
		case nil:
		default:
			return nil, fmt.Errorf("key %s: nested values are not supported", k)
		}
	}
	return out, nil
}

func fetch(ctx context.Context, c *http.Client, u string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFileValueBytes))
	return body, resp.StatusCode, err
}
