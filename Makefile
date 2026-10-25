.PHONY: generate test build run dev-db migrate grants seed admin keys up down logs

DEV_DB_APP   := postgres://rbac_app:app@localhost:5432/rbac?sslmode=disable
DEV_CONFIG   := --config-source file:.env.dev --config-source env

generate:                 ## regenerate wire_gen.go after changing providers
	go tool wire ./internal/app

test:
	go vet ./...
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/rbac-service ./cmd/rbac-service

# --- local development ---------------------------------------------------------
dev-db:                   ## PostgreSQL on :5432 with owner + app roles
	docker run -d --name rbac-dev-db -p 5432:5432 \
		-e POSTGRES_USER=rbac_owner -e POSTGRES_PASSWORD=owner -e POSTGRES_DB=rbac postgres:17-alpine
	until docker exec rbac-dev-db pg_isready -U rbac_owner -d rbac >/dev/null 2>&1; do sleep 1; done; sleep 1
	docker exec rbac-dev-db psql -U rbac_owner -d rbac -c "CREATE ROLE rbac_app LOGIN PASSWORD 'app'"

migrate:                  ## apply migrations/ with golang-migrate (as the owner role)
	docker run --rm --add-host=host.docker.internal:host-gateway -v $(PWD)/migrations:/migrations:ro \
		migrate/migrate:v4.18.1 -path=/migrations \
		-database "postgres://rbac_owner:owner@host.docker.internal:5432/rbac?sslmode=disable" up

grants:                   ## least-privilege grants for the app role
	docker exec -i rbac-dev-db psql -q -U rbac_owner -d rbac -v app_role=rbac_app < scripts/db/least_privilege.sql

.env.dev:
	@printf 'APP_ENV=development\nLOG_FORMAT=console\nJWT_ISSUER=http://localhost:8080\nDATABASE_URL=$(DEV_DB_APP)\n' > .env.dev
	@printf 'JWT_SIGNING_KEY=%s\n' "$$(go run ./cmd/rbac-service keys generate 2>/dev/null | base64 | tr -d '\n')" >> .env.dev
	@chmod 600 .env.dev

seed: .env.dev
	go run ./cmd/rbac-service seed $(DEV_CONFIG)

admin: .env.dev           ## make admin EMAIL=you@example.com
	go run ./cmd/rbac-service admin create --email $(EMAIL) $(DEV_CONFIG)

run: .env.dev
	go run ./cmd/rbac-service serve $(DEV_CONFIG)

# --- compose -------------------------------------------------------------------
keys:                     ## create the JWT signing key used by compose
	@# The directory (0700) protects the key on the host; the file must be
	@# readable by the container's non-root user, which has a different uid.
	@mkdir -p secrets && chmod 700 secrets
	@go run ./cmd/rbac-service keys generate > secrets/jwt_signing_key && chmod 444 secrets/jwt_signing_key

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f app
