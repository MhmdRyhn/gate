# rbac-service

An authentication and role-based access control service in Go, for applications with two audiences:

- **Internal users:** staff. Their access comes from roles and permissions.
- **Public users:** the application's customers. They sign up themselves, hold one or more public types (such as `customer` or `vendor`), and access rules are left to the business.

Users sign in with an **email or phone number** and a password. SSO hooks (OIDC/OAuth 2.0) are in place for adding providers later.

**Stack:** gin · gorm (PostgreSQL) · zap · Google Wire · cobra · EdDSA/RS256 JWT · Argon2id

```sh
make dev-db migrate grants seed     # local PostgreSQL, schema, grants, RBAC registry
make admin EMAIL=you@example.com    # first admin (password prompt)
make run                            # http://localhost:8080
```

## Documentation

| Doc | What it covers |
|---|---|
| [docs/guide.md](docs/guide.md) | Features, architecture, data model, configuration, CLI, API, extending the project |
| [docs/jwt.md](docs/jwt.md) | JWT standards, the token format used here, key rotation, verifying tokens in other services |
| [docs/sso.md](docs/sso.md) | Adding an SSO provider (Google, Microsoft Entra ID, Keycloak, ...) |
| [docs/security.md](docs/security.md) | Security controls in place, and the vulnerabilities to plan for at scale |
| [docs/deployment.md](docs/deployment.md) | Vendor-neutral deployment to a cloud VM, backups, migration, scaling |

## Repository layout

```
cmd/rbac-service/        main: hands over to the CLI
internal/cli/            cobra commands (serve, seed, admin, keys, config, maintenance, ...)
internal/app/            Wire providers and injectors (wire_gen.go is generated)
internal/config/         typed config + pluggable sources (env, file, dir, consul, http)
internal/domain/         entities and domain errors (no dependencies)
internal/rbac/           permissions, default roles, public user types (source of truth)
internal/auth/           Argon2id, JWT keys/JWKS/issuer, opaque tokens
internal/auth/sso/       SSO provider interface, policy, state/PKCE flow
internal/service/        use cases and authorization rules
internal/repository/     persistence interfaces; postgres/ = gorm implementation
internal/httpapi/        gin router, middleware, handlers, DTOs (RFC 9457 errors)
migrations/              SQL schema (golang-migrate format), applied outside the app
scripts/db/              least-privilege grants
deploy/                  Caddyfile, PostgreSQL init, backup/restore
```
