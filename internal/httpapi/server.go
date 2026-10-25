package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/config"
)

// Server is the HTTP server with graceful shutdown.
type Server struct {
	srv *http.Server
	cfg config.HTTPConfig
	log *zap.Logger
}

// NewServer wraps the router in an http.Server with conservative timeouts
// (slow-client protection).
func NewServer(cfg config.HTTPConfig, router *gin.Engine, log *zap.Logger) *Server {
	return &Server{
		cfg: cfg,
		log: log,
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           router,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    32 << 10,
		},
	}
}

// Run serves until ctx is cancelled, then drains in-flight requests for up
// to ShutdownTimeout.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening", zap.String("addr", s.cfg.Addr))
		errCh <- s.srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}
	s.log.Info("shutting down http server")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownTimeout)
	defer cancel()
	return s.srv.Shutdown(shutdownCtx)
}
