package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/parser"
)

// HTTPProbeStage handles HTTP probing and technology fingerprinting using httpx.
type HTTPProbeStage struct {
	deps *Deps
}

func NewHTTPProbeStage(deps *Deps) *HTTPProbeStage {
	return &HTTPProbeStage{deps: deps}
}

func (s *HTTPProbeStage) Name() string { return StageHTTPProbe }

func (s *HTTPProbeStage) Run(ctx context.Context, job broker.Job) (int, error) {
	var payload broker.HTTPProbePayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return 0, fmt.Errorf("unmarshal httpprobe payload: %w", err)
	}

	slog.Info("starting HTTP probing", "targets", len(payload.HostPorts), "target_list", payload.HostPorts, "scan_id", job.ScanID)

	// Write targets to a temp file — httpx has known issues reading from
	// /dev/stdin over a pipe in some versions. A temp file is more reliable.
	tmpFile, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetList := strings.Join(payload.HostPorts, "\n")
	if _, err := tmpFile.WriteString(targetList + "\n"); err != nil {
		tmpFile.Close()
		return 0, fmt.Errorf("write targets: %w", err)
	}
	tmpFile.Close()

	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Httpx, []string{
		"-list", tmpFile.Name(),
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-content-length",
		"-content-type",
		"-cdn",
		"-response-time",
		"-follow-redirects",
		"-silent",
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("run httpx: %w", err)
	}

	// Log raw output to help diagnose parsing issues.
	if len(result.Stdout) > 0 {
		raw := string(result.Stdout)
		if len(raw) > 2000 {
			raw = raw[:2000] + "...(truncated)"
		}
		slog.Info("httpx raw output", "bytes", len(result.Stdout), "output", raw)
	}

	httpResults, err := parser.ParseHTTPX(result.Stdout)
	if err != nil {
		return 0, fmt.Errorf("parse httpx output: %w", err)
	}

	slog.Info("HTTP probing complete", "live_services", len(httpResults))

	// Collect live URLs and technologies for next stages
	liveURLs := make([]string, 0, len(httpResults))
	allTechs := make(map[string]bool)

	for _, hr := range httpResults {
		liveURLs = append(liveURLs, hr.URL)

		for _, tech := range hr.Technologies {
			allTechs[tech] = true
		}

		// Log interesting findings
		if hr.StatusCode == 200 {
			slog.Info("live service found",
				"url", hr.URL,
				"title", hr.Title,
				"status", hr.StatusCode,
				"tech", hr.Technologies,
			)
		}
	}

	// Publish next stage: crawling
	if len(liveURLs) > 0 {
		err = s.deps.Broker.PublishToStage(ctx, broker.QueueCrawl, job.ScanID, broker.CrawlPayload{
			URLs: liveURLs,
		})
		if err != nil {
			return len(httpResults), fmt.Errorf("publish crawl job: %w", err)
		}
	}

	// Also publish to vuln scan with technology info for targeted scanning
	if len(liveURLs) > 0 {
		techs := make([]string, 0, len(allTechs))
		for t := range allTechs {
			techs = append(techs, t)
		}

		err = s.deps.Broker.PublishToStage(ctx, broker.QueueVulnScan, job.ScanID, broker.VulnScanPayload{
			URLs:         liveURLs,
			Technologies: techs,
		})
		if err != nil {
			return len(httpResults), fmt.Errorf("publish vulnscan job: %w", err)
		}
	} else {
		// No live HTTP services found — pipeline ends here, mark scan complete.
		slog.Info("no live services found, completing scan", "scan_id", job.ScanID)
		s.deps.ScanRepo.UpdateStatus(ctx, job.ScanID, database.ScanStatusCompleted)
		s.deps.Notifier.Send(ctx, notify.Event{
			Type:     "scan_complete",
			Severity: "info",
			Title:    "Scan Completed",
			Details:  "Scan completed — no live HTTP services found on discovered hosts.",
			ScanID:   job.ScanID,
		})
	}

	return len(httpResults), nil
}
