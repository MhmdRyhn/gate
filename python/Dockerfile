# syntax=docker/dockerfile:1

# --- build: resolve the locked dependencies into a virtualenv -------------------
FROM python:3.15-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first, so source changes do not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable

# --- runtime: no compiler, no uv, non-root -------------------------------------
FROM python:3.15-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
# The virtualenv lives at the same path as in the build stage, so its console
# scripts' interpreter paths stay valid.
COPY --from=build /app/.venv /app/.venv
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATE_VERSION=$VERSION \
    GATE_COMMIT=$COMMIT \
    GATE_BUILD_DATE=$BUILD_DATE
USER app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["rbac-service", "healthcheck"]
ENTRYPOINT ["rbac-service"]
CMD ["serve"]
