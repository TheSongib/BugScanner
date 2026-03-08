package pipeline

import (
	"context"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/config"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/repository"
	"github.com/brandon/bugscanner/internal/runner"
	"github.com/brandon/bugscanner/internal/scope"
)

// Stage names matching queue names.
const (
	StageDiscovery = "discovery"
	StagePortScan  = "portscan"
	StageHTTPProbe = "httpprobe"
	StageCrawl     = "crawl"
	StageVulnScan  = "vulnscan"
)

// NextQueue returns the next queue in the pipeline, or empty string if this is the last stage.
func NextQueue(currentStage string) string {
	switch currentStage {
	case StageDiscovery:
		return broker.QueuePortScan
	case StagePortScan:
		return broker.QueueHTTPProbe
	case StageHTTPProbe:
		return broker.QueueCrawl
	case StageCrawl:
		return broker.QueueVulnScan
	case StageVulnScan:
		return "" // final stage
	default:
		return ""
	}
}

// Stage defines the interface for a pipeline stage.
type Stage interface {
	Name() string
	Run(ctx context.Context, job broker.Job) (outputCount int, err error)
}

// Deps holds shared dependencies injected into all pipeline stages.
type Deps struct {
	Config     *config.Config
	Runner     *runner.Runner
	Broker     *broker.Broker
	Notifier   *notify.Dispatcher
	ScanRepo   *repository.ScanRepo
	DomainRepo *repository.DomainRepo
	SubRepo    *repository.SubdomainRepo
	IPRepo     *repository.IPRepo
	PortRepo   *repository.PortRepo
	TechRepo   *repository.TechnologyRepo
	VulnRepo   *repository.VulnerabilityRepo
}

// NewScopeValidator creates a scope validator from a discovery payload's scope config.
func NewScopeValidator(scopeIn, scopeOut []string) (*scope.Validator, error) {
	return scope.New(scopeIn, scopeOut)
}
