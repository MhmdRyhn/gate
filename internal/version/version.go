// Package version exposes build metadata, set at build time with:
//
//	go build -ldflags "-X github.com/MhmdRyhn/gate/internal/version.Version=1.2.3 \
//	  -X github.com/MhmdRyhn/gate/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/MhmdRyhn/gate/internal/version.BuildDate=$(date -u +%FT%TZ)"
package version

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
