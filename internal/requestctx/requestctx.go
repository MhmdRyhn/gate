// Package requestctx carries per-request metadata (request ID, client IP,
// user agent) through context.Context, so services can record it in sessions
// and audit events without depending on the transport layer.
package requestctx

import "context"

// Meta describes the request that triggered an operation.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

type key struct{}

// With returns a copy of ctx carrying m.
func With(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, key{}, m)
}

// From returns the Meta stored in ctx, or the zero Meta (e.g. CLI commands).
func From(ctx context.Context) Meta {
	m, _ := ctx.Value(key{}).(Meta)
	return m
}
