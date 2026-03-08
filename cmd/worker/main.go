package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/config"
	"github.com/brandon/bugscanner/internal/logging"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/pipeline"
	"github.com/brandon/bugscanner/internal/ratelimit"
	"github.com/brandon/bugscanner/internal/repository"
	"github.com/brandon/bugscanner/internal/runner"
)

func main() {
	// Structured logging (US Eastern timezone)
	logging.Setup()

	slog.Info("starting bug scanner worker")

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

	// Connect to RabbitMQ
	brk, err := broker.New(cfg.RabbitMQ)
	if err != nil {
		slog.Error("failed to connect to rabbitmq", "error", err)
		os.Exit(1)
	}
	defer brk.Close()

	// Connect to Redis for rate limiting
	limiter, err := ratelimit.New(cfg.Redis, cfg.RateLimit)
	if err != nil {
		slog.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer limiter.Close()

	// Initialize notifier
	notifier := notify.NewDispatcher(cfg.Notify)

	// Initialize runner
	cmdRunner := runner.New(limiter)

	// Initialize repositories
	scanRepo := repository.NewScanRepo(db.Pool)
	domainRepo := repository.NewDomainRepo(db.Pool)
	subRepo := repository.NewSubdomainRepo(db.Pool)
	ipRepo := repository.NewIPRepo(db.Pool)
	portRepo := repository.NewPortRepo(db.Pool)
	techRepo := repository.NewTechnologyRepo(db.Pool)
	vulnRepo := repository.NewVulnerabilityRepo(db.Pool)

	// Shared dependencies for pipeline stages
	deps := &pipeline.Deps{
		Config:     cfg,
		Runner:     cmdRunner,
		Broker:     brk,
		Notifier:   notifier,
		ScanRepo:   scanRepo,
		DomainRepo: domainRepo,
		SubRepo:    subRepo,
		IPRepo:     ipRepo,
		PortRepo:   portRepo,
		TechRepo:   techRepo,
		VulnRepo:   vulnRepo,
	}

	// Initialize pipeline stages
	stages := map[string]pipeline.Stage{
		broker.QueueDiscovery: pipeline.NewDiscoveryStage(deps),
		broker.QueuePortScan:  pipeline.NewPortScanStage(deps),
		broker.QueueHTTPProbe: pipeline.NewHTTPProbeStage(deps),
		broker.QueueCrawl:     pipeline.NewCrawlStage(deps),
		broker.QueueVulnScan:  pipeline.NewVulnScanStage(deps),
	}

	// Graceful shutdown on signals
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	// Start consumers for each pipeline queue
	g, gCtx := errgroup.WithContext(ctx)

	for queueName, stage := range stages {
		queueName := queueName
		stage := stage

		g.Go(func() error {
			handler := makeHandler(stage, scanRepo)
			slog.Info("starting consumer", "queue", queueName, "stage", stage.Name())
			return brk.Consume(gCtx, queueName, cfg.Worker.Concurrency, handler)
		})
	}

	slog.Info("worker running", "concurrency", cfg.Worker.Concurrency, "queues", len(stages))

	if err := g.Wait(); err != nil && err != context.Canceled {
		slog.Error("worker error", "error", err)
		os.Exit(1)
	}

	slog.Info("worker stopped")
}

// makeHandler wraps a pipeline stage as a broker handler with job tracking.
func makeHandler(stage pipeline.Stage, scanRepo *repository.ScanRepo) broker.Handler {
	return func(ctx context.Context, job broker.Job) error {
		// Create scan job record
		scanJob, err := scanRepo.CreateJob(ctx, job.ScanID, stage.Name())
		if err != nil {
			slog.Error("failed to create scan job", "error", err)
			// Continue even if tracking fails
		}

		// Update job status to running
		if scanJob != nil {
			scanRepo.UpdateJobStatus(ctx, scanJob.ID, database.ScanStatusRunning, 0, "")
		}

		// Run the pipeline stage
		outputCount, err := stage.Run(ctx, job)

		// Update job status
		if scanJob != nil {
			if err != nil {
				scanRepo.UpdateJobStatus(ctx, scanJob.ID, database.ScanStatusFailed, outputCount, err.Error())
			} else {
				scanRepo.UpdateJobStatus(ctx, scanJob.ID, database.ScanStatusCompleted, outputCount, "")
			}
		}

		return err
	}
}
