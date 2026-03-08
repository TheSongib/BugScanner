package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/notify"
	"github.com/brandon/bugscanner/internal/parser"
)

// VulnScanStage handles vulnerability scanning using nuclei.
type VulnScanStage struct {
	deps *Deps
}

func NewVulnScanStage(deps *Deps) *VulnScanStage {
	return &VulnScanStage{deps: deps}
}

func (s *VulnScanStage) Name() string { return StageVulnScan }

func (s *VulnScanStage) Run(ctx context.Context, job broker.Job) (int, error) {
	var payload broker.VulnScanPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return 0, fmt.Errorf("unmarshal vulnscan payload: %w", err)
	}

	slog.Info("starting vulnerability scan", "urls", len(payload.URLs), "scan_id", job.ScanID)

	// Write targets to a temp file for reliable input.
	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
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

	// Build nuclei args — run all templates (no -tags filter) for thorough coverage.
	// Technology detection from httpx is logged but not used to restrict templates,
	// since tag filtering excludes many important vulnerability checks.
	args := []string{
		"-list", tmpFile.Name(),
		"-json",
		"-severity", "info,low,medium,high,critical",
		"-silent",
		"-rate-limit", "50",
		"-bulk-size", "25",
		"-concurrency", "10",
	}

	result, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, args, nil, 30*time.Minute)
	if err != nil {
		return 0, fmt.Errorf("run nuclei: %w", err)
	}

	findings, err := parser.ParseNuclei(result.Stdout)
	if err != nil {
		return 0, fmt.Errorf("parse nuclei output: %w", err)
	}

	slog.Info("vulnerability scan complete", "findings", len(findings))

	// Store findings and send notifications
	for _, f := range findings {
		extractedJSON, _ := json.Marshal(f.ExtractedData)

		vuln := &database.Vulnerability{
			ScanID:        job.ScanID,
			TemplateID:    f.TemplateID,
			TemplateName:  f.TemplateName,
			Severity:      database.Severity(f.Severity),
			MatchedURL:    f.MatchedURL,
			MatchedAt:     f.MatchedAt,
			ExtractedData: extractedJSON,
			CurlCommand:   f.CurlCommand,
			Reference:     f.Reference,
		}

		_, err := s.deps.VulnRepo.Create(ctx, vuln)
		if err != nil {
			slog.Warn("failed to store vulnerability",
				"template", f.TemplateID,
				"url", f.MatchedURL,
				"error", err,
			)
			continue
		}

		// Send notification for significant findings
		s.deps.Notifier.Send(ctx, notify.Event{
			Type:     "new_vuln",
			Severity: f.Severity,
			Title:    fmt.Sprintf("%s - %s", f.TemplateName, f.Severity),
			Details:  fmt.Sprintf("**Template:** %s\n**URL:** %s\n**Description:** %s", f.TemplateID, f.MatchedURL, f.Description),
			URL:      f.MatchedURL,
			ScanID:   job.ScanID,
		})

		slog.Info("vulnerability found",
			"template", f.TemplateID,
			"severity", f.Severity,
			"url", f.MatchedURL,
		)
	}

	// Mark scan as completed if this is the final stage
	if err := s.deps.ScanRepo.UpdateStatus(ctx, job.ScanID, database.ScanStatusCompleted); err != nil {
		slog.Warn("failed to update scan status", "error", err)
	}

	// Send scan completion notification
	s.deps.Notifier.Send(ctx, notify.Event{
		Type:     "scan_complete",
		Severity: "info",
		Title:    "Scan Completed",
		Details:  fmt.Sprintf("Scan %s completed with %d findings", job.ScanID, len(findings)),
		ScanID:   job.ScanID,
	})

	return len(findings), nil
}

// buildTemplateTags converts detected technologies to nuclei template tags.
func buildTemplateTags(technologies []string) string {
	tagMap := map[string]string{
		"apache":      "apache",
		"nginx":       "nginx",
		"iis":         "iis",
		"tomcat":      "tomcat",
		"wordpress":   "wordpress",
		"joomla":      "joomla",
		"drupal":      "drupal",
		"jenkins":     "jenkins",
		"jira":        "jira",
		"confluence":  "confluence",
		"grafana":     "grafana",
		"gitlab":      "gitlab",
		"kibana":      "kibana",
		"elasticsearch": "elasticsearch",
		"docker":      "docker",
		"kubernetes":  "kubernetes",
		"php":         "php",
		"java":        "java",
		"node.js":     "nodejs",
		"react":       "react",
		"angular":     "angular",
		"spring":      "spring",
		"laravel":     "laravel",
		"django":      "django",
		"flask":       "flask",
		"aws":         "aws",
		"azure":       "azure",
		"gcp":         "gcp",
	}

	var tags []string
	seen := make(map[string]bool)

	for _, tech := range technologies {
		techLower := strings.ToLower(tech)
		for key, tag := range tagMap {
			if strings.Contains(techLower, key) && !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}

	// Always include common vulnerability categories
	defaultTags := []string{"cve", "misconfig", "exposure", "takeover", "default-login"}
	for _, t := range defaultTags {
		if !seen[t] {
			tags = append(tags, t)
		}
	}

	return strings.Join(tags, ",")
}
