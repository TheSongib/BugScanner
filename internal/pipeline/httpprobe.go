package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

	// Brief pause to allow any transient network state from naabu's port scan to settle.
	// With the web-port-only scan (20 ports at 300/s), conntrack recovers instantly,
	// but a small buffer guards against edge cases.
	slog.Info("waiting before HTTP probing", "delay", "5s")
	time.Sleep(5 * time.Second)

	slog.Info("starting HTTP probing", "targets", len(payload.HostPorts), "target_list", payload.HostPorts, "scan_id", job.ScanID)

	// Use -u flag with comma-separated targets to avoid temp-file + stdin interaction issues.
	targetArg := strings.Join(payload.HostPorts, ",")
	slog.Info("httpx target arg", "targets", targetArg)

	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Httpx, []string{
		"-u", targetArg,
		"-no-fallback-scheme", // use only the scheme from the input URL (don't auto-try https for http:// inputs)
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
		"-timeout", "10",
		"-retries", "3", // retry up to 3x: naabu SYN scan briefly disrupts Docker conntrack (~10s to recover)
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
