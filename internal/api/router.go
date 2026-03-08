package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/repository"
)

// Server holds all API dependencies.
type Server struct {
	scanRepo *repository.ScanRepo
	domainRepo *repository.DomainRepo
	subRepo  *repository.SubdomainRepo
	vulnRepo *repository.VulnerabilityRepo
	broker   *broker.Broker
	notifier *notify.Dispatcher
}

// NewServer creates a new API server.
func NewServer(
	scanRepo *repository.ScanRepo,
	domainRepo *repository.DomainRepo,
	subRepo *repository.SubdomainRepo,
	vulnRepo *repository.VulnerabilityRepo,
	broker *broker.Broker,
	notifier *notify.Dispatcher,
) *Server {
	return &Server{
		scanRepo: scanRepo,
		domainRepo: domainRepo,
		subRepo:  subRepo,
		vulnRepo: vulnRepo,
		broker:   broker,
		notifier: notifier,
	}
}

// Router returns the configured HTTP router.
func (s *Server) Router() *chi.Mux {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(CORSMiddleware)

	// Health check
	r.Get("/health", s.handleHealth)

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Scans
		r.Route("/scans", func(r chi.Router) {
			r.Post("/", s.handleCreateScan)
			r.Get("/", s.handleListScans)
			r.Get("/{scanID}", s.handleGetScan)
			r.Get("/{scanID}/results", s.handleGetScanResults)
			r.Post("/{scanID}/cancel", s.handleCancelScan)
		})

		// Vulnerabilities
		r.Route("/vulnerabilities", func(r chi.Router) {
			r.Get("/", s.handleListVulnerabilities)
			r.Post("/{vulnID}/false-positive", s.handleMarkFalsePositive)
			r.Post("/{vulnID}/triage", s.handleMarkTriaged)
		})
	})

	return r
}
