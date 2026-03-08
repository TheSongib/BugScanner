package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/parser"
)

// CrawlStage handles web crawling and spidering using katana.
type CrawlStage struct {
	deps *Deps
}

func NewCrawlStage(deps *Deps) *CrawlStage {
	return &CrawlStage{deps: deps}
}

func (s *CrawlStage) Name() string { return StageCrawl }

func (s *CrawlStage) Run(ctx context.Context, job broker.Job) (int, error) {
	var payload broker.CrawlPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return 0, fmt.Errorf("unmarshal crawl payload: %w", err)
	}

	slog.Info("starting crawl", "urls", len(payload.URLs), "scan_id", job.ScanID)

	// Write targets to a temp file for reliable input.
	tmpFile, err := os.CreateTemp("", "katana-targets-*.txt")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetList := strings.Join(payload.URLs, "\n")
	if _, err := tmpFile.WriteString(targetList + "\n"); err != nil {
		tmpFile.Close()
		return 0, fmt.Errorf("write targets: %w", err)
	}
	tmpFile.Close()

	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Katana, []string{
		"-list", tmpFile.Name(),
		"-json",
		"-depth", "3",
		"-js-crawl",
		"-known-files", "all",
		"-form-extraction",
		"-silent",
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("run katana: %w", err)
	}

	crawlResults, err := parser.ParseKatana(result.Stdout)
	if err != nil {
		return 0, fmt.Errorf("parse katana output: %w", err)
	}

	slog.Info("crawl complete", "urls_discovered", len(crawlResults))

	// The crawl stage feeds additional URLs back to the vuln scan stage.
	// The httpprobe stage already published the initial set of URLs to vulnscan,
	// so here we only add newly discovered endpoints.
	if len(crawlResults) > 0 {
		crawledURLs := make([]string, 0, len(crawlResults))
		for _, cr := range crawlResults {
			// Only pass absolute URLs to nuclei — skip relative paths
			// that katana may return (nuclei can't scan without a host).
			if !strings.HasPrefix(cr.URL, "http://") && !strings.HasPrefix(cr.URL, "https://") {
				continue
			}
			crawledURLs = append(crawledURLs, cr.URL)
		}

		err = s.deps.Broker.PublishToStage(ctx, broker.QueueVulnScan, job.ScanID, broker.VulnScanPayload{
			URLs: crawledURLs,
		})
		if err != nil {
			return len(crawlResults), fmt.Errorf("publish vulnscan job: %w", err)
		}
	}

	return len(crawlResults), nil
}
