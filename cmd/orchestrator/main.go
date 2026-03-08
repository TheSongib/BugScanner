package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brandon/bugscanner/internal/api"
	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/config"
	"github.com/brandon/bugscanner/internal/logging"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/repository"
)

func main() {
	// Structured logging (US Eastern timezone)
	logging.Setup()

	slog.Info("starting bug scanner orchestrator")

	// Load config
	cfg, err := config.Load("")
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL
	db, err := database.New(ctx, cfg.Database)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run migrations
	if err := db.RunMigrations(ctx, cfg.Database.MigrationsPath); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	slog.Info("database migrations complete")

	// Connect to RabbitMQ
	brk, err := broker.New(cfg.RabbitMQ)
	if err != nil {
		slog.Error("failed to connect to rabbitmq", "error", err)
		os.Exit(1)
	}
	defer brk.Close()
	slog.Info("connected to rabbitmq")

	// Initialize notifier
	notifier := notify.NewDispatcher(cfg.Notify)

	// Initialize repositories
	scanRepo := repository.NewScanRepo(db.Pool)
	domainRepo := repository.NewDomainRepo(db.Pool)
	subRepo := repository.NewSubdomainRepo(db.Pool)
	vulnRepo := repository.NewVulnerabilityRepo(db.Pool)

	// Create API server
	server := api.NewServer(scanRepo, domainRepo, subRepo, vulnRepo, brk, notifier)
	router := server.Router()

	// Start HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		slog.Info("shutting down orchestrator...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("http server shutdown error", "error", err)
		}
	}()

	slog.Info("orchestrator listening", "addr", addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http server error", "error", err)
		os.Exit(1)
	}

	slog.Info("orchestrator stopped")
}
