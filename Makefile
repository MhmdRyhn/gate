.PHONY: generate test build run dev-db migrate grants seed admin keys up down logs

DEV_DB_APP   := postgres://gate_app:app@localhost:5432/gate?sslmode=disable
DEV_CONFIG   := --config-source file:.env.dev --config-source env

generate:                 ## regenerate wire_gen.go after changing providers
	go tool wire ./internal/app

test:
	go vet ./...
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/gate ./cmd

# --- local development ---------------------------------------------------------
dev-db:                   ## PostgreSQL on :5432 with owner + app roles
	docker run -d --name gate-dev-db -p 5432:5432 \
		-e POSTGRES_USER=gate_owner -e POSTGRES_PASSWORD=owner -e POSTGRES_DB=gate postgres:17-alpine
	until docker exec gate-dev-db pg_isready -U gate_owner -d gate >/dev/null 2>&1; do sleep 1; done; sleep 1
	docker exec gate-dev-db psql -U gate_owner -d gate -c "CREATE ROLE gate_app LOGIN PASSWORD 'app'"

migrate:                  ## apply migrations/ with golang-migrate (as the owner role)
	docker run --rm --add-host=host.docker.internal:host-gateway -v $(PWD)/migrations:/migrations:ro \
		migrate/migrate:v4.18.1 -path=/migrations \
		-database "postgres://gate_owner:owner@host.docker.internal:5432/gate?sslmode=disable" up

grants:                   ## least-privilege grants for the app role
	docker exec -i gate-dev-db psql -q -U gate_owner -d gate -v app_role=gate_app < scripts/db/least_privilege.sql

.env.dev:
	@printf 'APP_ENV=development\nLOG_FORMAT=console\nJWT_ISSUER=http://localhost:8080\nDATABASE_URL=$(DEV_DB_APP)\n' > .env.dev
	@printf 'JWT_SIGNING_KEY=%s\n' "$$(go run ./cmd keys generate 2>/dev/null | base64 | tr -d '\n')" >> .env.dev
	@chmod 600 .env.dev

seed: .env.dev
	go run ./cmd seed $(DEV_CONFIG)

admin: .env.dev           ## make admin EMAIL=you@example.com
	go run ./cmd admin create --email $(EMAIL) $(DEV_CONFIG)

run: .env.dev
	go run ./cmd serve $(DEV_CONFIG)

# --- compose -------------------------------------------------------------------
keys:                     ## create the JWT signing key used by compose
	@# The directory (0700) protects the key on the host; the file must be
	@# readable by the container's non-root user, which has a different uid.
	@mkdir -p secrets && chmod 700 secrets
	@go run ./cmd keys generate > secrets/jwt_signing_key && chmod 444 secrets/jwt_signing_key

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f app
