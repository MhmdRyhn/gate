# rbac-service (Python)

A Python 3.15 implementation of the authentication and role-based access control service in the repository root. It has the same API, rules and CLI as the Go service, and runs against **the same database schema** (`../migrations`).

It is a drop-in alternative to the Go service:

- **Password hashes:** Argon2id hashes stored by the Go service verify here, and the reverse.
- **Tokens:** access tokens, JWKS and key IDs are identical, so services that verify tokens accept either implementation.
- **Configuration:** the same keys (`DATABASE_URL`, `JWT_SIGNING_KEY`, ...) and the same config sources (`env`, `file:`, `dir:`, `consul:`, `http:`).

The Go service in the parent directory is unchanged.

**Stack:** FastAPI on uvicorn (uvloop + httptools) · SQLAlchemy 2.1 Core on asyncpg · Pydantic v2 · PyJWT/cryptography (EdDSA, RS256) · argon2-cffi · structlog · Typer · uv

```sh
make install                          # Python 3.15 virtualenv from uv.lock
make dev-db migrate grants seed       # local PostgreSQL, schema, grants, RBAC registry
make admin EMAIL=you@example.com      # first admin (password prompt)
make run                              # http://localhost:8080
make test lint                        # pytest; ruff + mypy --strict
```

Deployment on AWS EC2: **[DEPLOY_AWS.md](DEPLOY_AWS.md)**. The feature, API, JWT and SSO documentation in `../docs/` applies to this implementation as well.

## Design

### Built for high traffic

- **Fully async I/O.** Every request handler, dependency and database call is `async`, so no request ever runs in FastAPI's thread pool, and no database or network call blocks the event loop. PostgreSQL access is SQLAlchemy Core on asyncpg, the fastest Python driver (see [Database access](#database-access)).
- **One worker process per CPU.** `serve` starts N uvicorn workers (`HTTP_WORKERS`, default one per CPU) on uvloop with the httptools parser. Each worker serves thousands of concurrent connections; together the processes use every core.
- **CPU-heavy work stays off the event loop.** Argon2id password hashing runs on a small dedicated thread pool per worker (argon2's C code releases the GIL). A burst of logins therefore neither stalls other requests nor exhausts memory.
- **One database round trip per authenticated request.** The check that turns a token into a principal (session valid, user active, effective permissions, public types) is a single indexed query.
- **Thin request path.** One pure-ASGI middleware handles request ID, client IP, security headers, body limit, crash recovery and access log. Static responses (JWKS, registry lists) are built once. Audit events are written in the background, with back-pressure, so they add no latency.
- **Back-pressure instead of collapse.** `HTTP_MAX_CONCURRENCY` makes a saturated worker answer 503 at once; the listen backlog, keep-alive timeout and graceful drain are all configurable.

A quick local measurement with 2 workers on a laptop (PostgreSQL in Docker): about 2,200 req/s for an authenticated `GET /v1/me`, which runs 3 queries, at a 20 ms median with 50 concurrent clients, and about 18,000 req/s for `/healthz`. Load-test your own deployment before relying on any number.

### Database access

The schema is defined once for queries in `repository/postgres/tables.py` (SQLAlchemy Core `Table`s). The schema itself still belongs to `../migrations`; the app never runs DDL. A test fails if a table or column differs from the migration.

Every query is written with SQLAlchemy Core. SQLAlchemy owns the connection pool, connection recycling (`DB_CONN_MAX_LIFETIME`) and transactions. The ORM is not used: its identity map and unit of work cost CPU on every row, and it cannot map onto frozen dataclasses.

To keep SQLAlchemy from slowing the hot paths:
- **Static queries are compiled once at import.** This covers authentication, login, refresh, `/me` and the list endpoints (one compiled statement per filter combination). At runtime they only bind parameters and run on the asyncpg connection of a pooled SQLAlchemy connection, skipping SQLAlchemy's per-execute work (cache-key generation, greenlet hop, `Row` construction).
- **Rare dynamic statements use SQLAlchemy's normal `execute()`.** These are partial user updates and audit inserts, which run in the background.
- **AUTOCOMMIT is the engine default**, so a single query costs one round trip, not three (`BEGIN`, query, `ROLLBACK`). Multi-statement writes run inside a real transaction (`Database.transaction()`); an integration test proves a failed one leaves nothing behind.

Measured CPU per query, in-process with 32 concurrent tasks against PostgreSQL 17:

| Path | CPU per query |
|---|---|
| Raw asyncpg pool (previous implementation) | ~40–55 µs |
| SQLAlchemy `Connection.execute`, out of the box | ~90 µs |
| This implementation (SQLAlchemy pool + prepared statements) | ~50–65 µs |

The remaining ~10 µs is SQLAlchemy's pool checkout, the price of letting it own the connections. On the HTTP benchmark (`/v1/me`, `/v1/admin/roles`, `/v1/admin/users`, 2 workers) the results were within the run-to-run noise of the raw-asyncpg version.

### Request validation

Every request body is a frozen Pydantic v2 model in `web/dto.py`. Pydantic's validation core is written in Rust. FastAPI validates the body before the handler runs:
- required fields and length limits per field
- list sizes
- enums (`kind`, `status`)
- UUIDs
- unknown fields are rejected

Path IDs are parsed as UUIDs, and the query parameters `limit`, `offset`, `kind` and `actor_user_id` are checked in the routes. Failures become `400` problem+json responses with readable messages, like `password is required` or `unknown field "admin"`.

The rules that depend on data (email/phone normalisation, password policy, known permissions, privilege escalation) live in the services. That way they apply to the CLI too, not just HTTP.

### Immutable by default

- **Domain entities** (`gate/domain/models.py`) are `@dataclass(frozen=True, slots=True, kw_only=True)`. Fields cannot be reassigned, there is no per-instance `__dict__`, and construction is keyword-only. Changes produce new objects with `dataclasses.replace()`.
- **Collections are immutable too:**
  - lists → `tuple`
  - sets → `frozenset`
  - mappings → `frozendict`, new in Python 3.15 (PEP 814)
- **Repositories** return new entities and tuples; they never mutate their arguments.
- **Configuration** is a tree of frozen dataclasses; secrets are a `Secret` type that prints as `[REDACTED]`.
- **Constants** are `Final`: the RBAC registry (permissions, roles, public types) is tuples of frozen dataclasses.
- **Request and response bodies** are frozen Pydantic models with `extra="forbid"`, so unknown fields are rejected, as in the Go service.
- **Services** take their dependencies through keyword-only constructors and store them in `Final` slots.

### Layout

```
src/gate/
  domain/          entities (frozen dataclasses) and domain errors
  rbac.py          permissions, default roles, public user types (source of truth)
  config/          typed config, Go-style durations, pluggable sources
  auth/            Argon2id, JWT keys/JWKS/issuer, opaque tokens; sso/ = provider protocol + PKCE flow
  repository/      persistence protocols; postgres/ = SQLAlchemy Core tables + queries on asyncpg
  service/         use cases and data-dependent authorization rules
  web/             FastAPI app, middleware, dependencies (route-level access), DTOs, RFC 9457 errors
  container.py     composition root (replaces Google Wire)
  cli.py           Typer CLI: serve, seed, admin, keys, config, maintenance, healthcheck, version
tests/             unit and HTTP tests, fixtures produced by the Go service; integration/ = PostgreSQL tests
```

## Differences from the Go service

| Topic | Go | Python |
|---|---|---|
| Concurrency | goroutines in one process | asyncio event loop per worker × `HTTP_WORKERS` processes |
| Database pool | `DB_MAX_OPEN_CONNS` per process | `DB_MAX_OPEN_CONNS` **per worker**; default lowered from 25 to 10 |
| Login rate limiter | per process | per worker process (use a WAF/edge limit for a global one) |
| Server timeouts | `HTTP_READ_*`/`HTTP_WRITE_TIMEOUT` | not supported by uvicorn: ignored; put Caddy/ALB in front for slow-client protection |
| New settings | — | `HTTP_WORKERS`, `HTTP_MAX_CONCURRENCY`, `HTTP_BACKLOG`, `PASSWORD_HASH_THREADS`, `DB_STATEMENT_TIMEOUT`, `DB_STATEMENT_CACHE_SIZE`, `DB_POOL_TIMEOUT` |
| `DB_MAX_IDLE_CONNS` | idle connections kept | connections each worker opens at startup (connections then stay open) |
| Ignored settings | — | `DB_CONN_MAX_IDLE_TIME` (SQLAlchemy's pool has no idle timeout; `DB_CONN_MAX_LIFETIME` recycles connections) |
| API docs | none | `/docs` and `/openapi.json` only when `APP_ENV=development` |
| Build metadata | `-ldflags` | `GATE_VERSION`/`GATE_COMMIT`/`GATE_BUILD_DATE` env, set by the Docker build |

Error bodies, status codes, routes and audit actions are the same.

## Tests

`make test` runs the Go test suite ported to pytest, plus HTTP tests for the middleware. Coverage:
- RBAC registry, input normalisation and the privilege-escalation guard.
- Tokens, keys, password hashing.
- The SSO state/PKCE flow.
- All config sources.
- Route authorization, request IDs, validation errors, body limits, rate limiting, trusted proxies.
- The full SSO HTTP flow.

`tests/fixtures/go_compat.json` was produced by the Go code. The tests check that a Go password hash verifies, and that a Go access token is accepted with the same key ID.

`tests/test_tables.py` checks that the SQLAlchemy table definitions match `../migrations`.

`tests/integration/` tests the repositories against a real PostgreSQL. It applies the migrations, runs, then applies the down migration. It is skipped unless `GATE_TEST_DATABASE_URL` is set; `make test-integration` starts a throwaway PostgreSQL in Docker for it. Coverage:
- transaction rollback
- unique and foreign-key conflicts
- the one-query principal lookup
- refresh rotation and reuse detection, and session purge
- the SSO identity lookup
- role CRUD, idempotent seeding
- the audit log's jsonb round trip
