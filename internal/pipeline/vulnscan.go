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

	// Four-pass nuclei scan:
	// Pass 1 — standard http/ templates: passive checks, CVE detection, exposure, misconfigs.
	//           Runs ~9000 templates. The -dast flag cannot be combined — it replaces the
	//           template set rather than extending it.
	// Pass 2 — DAST mode (-dast): activates the fuzzing engine for SQLi, XSS, LFI etc.
	//           Only 54 templates but actively fuzzes discovered parameters.
	// Pass 3 — Custom detection templates: GraphQL, host-header injection, CORS bypass,
	//           CRLF injection, cache poisoning, prompt injection, open redirects, etc.
	// Pass 4 — Custom DAST fuzzing templates: blind XSS OOB, NoSQL injection, SSRF via
	//           webhook params, prototype pollution.
	commonArgs := []string{
		"-list", tmpFile.Name(),
		"-jsonl",
		"-severity", "info,low,medium,high,critical",
		"-silent",
		"-rate-limit", "50",
		"-bulk-size", "25",
		"-concurrency", "10",
	}

	passiveArgs := append([]string{"-t", "/root/nuclei-templates/http/"}, commonArgs...)
	dastArgs := append([]string{"-dast"}, commonArgs...)
	customArgs := append([]string{"-t", "/root/custom-templates/detection/"}, commonArgs...)
	customDastArgs := append([]string{"-dast", "-t", "/root/custom-templates/fuzz/"}, commonArgs...)

	var allOutput []byte

	slog.Info("nuclei pass 1: passive/http templates", "scan_id", job.ScanID)
	passiveResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, passiveArgs, nil, 20*time.Minute)
	if err != nil {
		slog.Warn("nuclei passive pass failed", "error", err)
	} else {
		slog.Info("nuclei passive pass complete", "bytes", len(passiveResult.Stdout))
		allOutput = append(allOutput, passiveResult.Stdout...)
	}

	slog.Info("nuclei pass 2: DAST fuzzing", "scan_id", job.ScanID)
	dastResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, dastArgs, nil, 15*time.Minute)
	if err != nil {
		slog.Warn("nuclei DAST pass failed", "error", err)
	} else {
		slog.Info("nuclei DAST pass complete", "bytes", len(dastResult.Stdout))
		allOutput = append(allOutput, dastResult.Stdout...)
	}

	slog.Info("nuclei pass 3: custom detection templates", "scan_id", job.ScanID)
	customResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, customArgs, nil, 10*time.Minute)
	if err != nil {
		slog.Warn("nuclei custom detection pass failed", "error", err)
	} else {
		slog.Info("nuclei custom detection pass complete", "bytes", len(customResult.Stdout))
		allOutput = append(allOutput, customResult.Stdout...)
	}

	slog.Info("nuclei pass 4: custom DAST fuzzing templates", "scan_id", job.ScanID)
	customDastResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, customDastArgs, nil, 12*time.Minute)
	if err != nil {
		slog.Warn("nuclei custom DAST pass failed", "error", err)
	} else {
		slog.Info("nuclei custom DAST pass complete", "bytes", len(customDastResult.Stdout))
		allOutput = append(allOutput, customDastResult.Stdout...)
	}

	if len(allOutput) > 0 {
		raw := string(allOutput)
		if len(raw) > 2000 {
			raw = raw[:2000] + "...(truncated)"
		}
		slog.Info("nuclei combined output", "bytes", len(allOutput), "output", raw)
	}

	findings, err := parser.ParseNuclei(allOutput)
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
