# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/MhmdRyhn/gate/internal/version.Version=${VERSION} -X github.com/MhmdRyhn/gate/internal/version.Commit=${COMMIT} -X github.com/MhmdRyhn/gate/internal/version.BuildDate=$(date -u +%FT%TZ)" \
    -o /out/rbac-service ./cmd/rbac-service

# Static binary on a minimal, shell-less, non-root base image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rbac-service /rbac-service
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["/rbac-service", "healthcheck"]
ENTRYPOINT ["/rbac-service"]
CMD ["serve"]
