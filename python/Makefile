.PHONY: install test test-integration lint run dev-db migrate grants seed admin keys image up down logs

DEV_DB_APP := postgres://rbac_app:app@localhost:5432/rbac?sslmode=disable
DEV_CONFIG := --config-source file:.env.dev --config-source env
RUN        := uv run rbac-service

install:                  ## virtualenv with the locked dependencies (installs Python 3.15 if needed)
	uv sync

test:
	uv run pytest

test-integration:         ## repository tests against a throwaway PostgreSQL 17
	docker run -d --rm --name rbac-py-test -p 55433:5432 -e POSTGRES_PASSWORD=pw postgres:17-alpine
	until docker exec rbac-py-test pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done; sleep 1
	GATE_TEST_DATABASE_URL=postgres://postgres:pw@localhost:55433/postgres uv run pytest; \
		status=$$?; docker stop rbac-py-test >/dev/null; exit $$status

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

# --- local development ---------------------------------------------------------
# Same database setup as the Go service; the schema lives in ../migrations.
dev-db:                   ## PostgreSQL on :5432 with owner + app roles
	docker run -d --name rbac-dev-db -p 5432:5432 \
		-e POSTGRES_USER=rbac_owner -e POSTGRES_PASSWORD=owner -e POSTGRES_DB=rbac postgres:17-alpine
	until docker exec rbac-dev-db pg_isready -U rbac_owner -d rbac >/dev/null 2>&1; do sleep 1; done; sleep 1
	docker exec rbac-dev-db psql -U rbac_owner -d rbac -c "CREATE ROLE rbac_app LOGIN PASSWORD 'app'"

migrate:                  ## apply ../migrations with golang-migrate (as the owner role)
	docker run --rm --add-host=host.docker.internal:host-gateway -v $(abspath ../migrations):/migrations:ro \
		migrate/migrate:v4.18.1 -path=/migrations \
		-database "postgres://rbac_owner:owner@host.docker.internal:5432/rbac?sslmode=disable" up

grants:                   ## least-privilege grants for the app role
	docker exec -i rbac-dev-db psql -q -U rbac_owner -d rbac -v app_role=rbac_app < ../scripts/db/least_privilege.sql

.env.dev:
	@printf 'APP_ENV=development\nLOG_FORMAT=console\nJWT_ISSUER=http://localhost:8080\nDATABASE_URL=$(DEV_DB_APP)\nHTTP_WORKERS=2\n' > .env.dev
	@printf 'JWT_SIGNING_KEY=%s\n' "$$($(RUN) keys generate 2>/dev/null | base64 | tr -d '\n')" >> .env.dev
	@chmod 600 .env.dev

seed: .env.dev
	$(RUN) seed $(DEV_CONFIG)

admin: .env.dev           ## make admin EMAIL=you@example.com
	$(RUN) admin create --email $(EMAIL) $(DEV_CONFIG)

run: .env.dev
	$(RUN) serve $(DEV_CONFIG)

# --- compose -------------------------------------------------------------------
keys:                     ## create the JWT signing key used by compose
	@# The directory (0700) protects the key on the host; the file must be
	@# readable by the container's non-root user, which has a different uid.
	@mkdir -p secrets && chmod 700 secrets
	@$(RUN) keys generate > secrets/jwt_signing_key && chmod 444 secrets/jwt_signing_key

image:                    ## build the image with version metadata
	docker build -t rbac-service-py:latest \
		--build-arg VERSION=$$(git describe --tags --always 2>/dev/null || echo dev) \
		--build-arg COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
		--build-arg BUILD_DATE=$$(date -u +%FT%TZ) .

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f app
