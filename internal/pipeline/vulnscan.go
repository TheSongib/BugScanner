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
	// Pass 1 — Passive: exposures, misconfigurations, exposed panels (~700 templates, 8 min).
	//           Covers backup files, git exposure, open redirects, server misconfigs,
	//           and exposed admin panels (Kubernetes, Grafana, Jenkins, etc.).
	// Pass 2 — DAST fuzzing (-dast): SQLi, XSS, LFI, open redirect bypass, BAC parameter
	//           escalation, and other injection classes via active parameter fuzzing.
	// Pass 3 — POST form DAST: same fuzzing engine applied to HTML form POST bodies,
	//           catching SQLi/XSS in login forms, search boxes, profile pages, etc.
	// Pass 4 — CVE scan: critical + high severity CVE templates only (~1500 templates, 20 min).
	//           Targets known exploitable vulnerabilities (RCE, auth bypass, SSRF, SQLi CVEs).
	//           Kept as a separate pass with its own timeout and severity filter to avoid
	//           blowing up Pass 1 timing by running all 9000+ templates together.
	commonArgs := []string{
		"-list", tmpFile.Name(),
		"-jsonl",
		"-severity", "info,low,medium,high,critical",
		"-silent",
		"-rate-limit", "50",
		"-bulk-size", "25",
		"-concurrency", "10",
	}

	// Pass 1 targets: exposures + misconfigurations + exposed panels.
	// Running the full http/ tree (9000+ templates) consistently exceeds the timeout.
	// These directories cover backup files, source disclosure, phpinfo, git exposure,
	// open redirects, server misconfigs, and exposed admin panels (Kubernetes dashboard,
	// ingress-nginx, Grafana, Jenkins, etc.) — the high-value passive findings for bug bounties.
	passiveArgs := append([]string{
		"-t", "/root/nuclei-templates/http/exposures/",
		"-t", "/root/nuclei-templates/http/misconfiguration/",
		"-t", "/root/nuclei-templates/http/exposed-panels/",
	}, commonArgs...)
	// Include custom templates alongside built-in DAST templates.
	// /root/custom-templates/ is populated at image build time from nuclei-templates/custom/.
	dastArgs := append([]string{"-dast", "-t", "/root/custom-templates/"}, commonArgs...)

	// Pass 4 — CVE scan: critical + high severity only.
	// Built independently of commonArgs so we can override -severity without duplicating flags.
	// 20-minute timeout accommodates ~1500 templates without rushing the scan.
	cveArgs := []string{
		"-t", "/root/nuclei-templates/http/cves/",
		"-list", tmpFile.Name(),
		"-jsonl",
		"-severity", "critical,high",
		"-silent",
		"-rate-limit", "50",
		"-bulk-size", "25",
		"-concurrency", "10",
	}

	var allOutput []byte

	slog.Info("nuclei pass 1: exposures + misconfiguration templates", "scan_id", job.ScanID)
	passiveResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, passiveArgs, nil, 8*time.Minute)
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

	// Pass 3 — POST form fuzzing.
	// Uses katana's raw form JSONL lines as input (-im jsonl) so nuclei can
	// parse form field names and fuzz POST body parameters. This catches
	// SQLi/XSS in login forms, search forms, profile pages, etc. that are
	// invisible to plain URL-based fuzzing.
	if len(payload.FormTargets) > 0 {
		formFile, err := os.CreateTemp("", "nuclei-forms-*.jsonl")
		if err != nil {
			slog.Warn("could not create form targets file, skipping POST fuzzing", "error", err)
		} else {
			defer os.Remove(formFile.Name())
			for _, line := range payload.FormTargets {
				if _, err := formFile.WriteString(line + "\n"); err != nil {
					slog.Warn("failed to write form target to temp file; POST fuzzing input may be incomplete", "error", err)
					break
				}
			}
			formFile.Close()

			// Reuse common nuclei flags but drop any existing -list argument so we can
			// safely substitute the form targets file, without depending on the
			// positional layout of commonArgs.
			withoutList := func(args []string) []string {
				filtered := make([]string, 0, len(args))
				for i := 0; i < len(args); i++ {
					if args[i] == "-list" {
						// Skip "-list" and its value (if present).
						if i+1 < len(args) {
							i++
						}
						continue
					}
					filtered = append(filtered, args[i])
				}
				return filtered
			}

			formArgs := append([]string{"-dast", "-im", "jsonl", "-list", formFile.Name()},
				withoutList(commonArgs)...) // reuse rate/concurrency flags but skip the URL -list
			slog.Info("nuclei pass 3: POST form DAST fuzzing", "forms", len(payload.FormTargets), "scan_id", job.ScanID)
			formResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, formArgs, nil, 10*time.Minute)
			if err != nil {
				slog.Warn("nuclei form DAST pass failed", "error", err)
			} else {
				slog.Info("nuclei form DAST pass complete", "bytes", len(formResult.Stdout))
				allOutput = append(allOutput, formResult.Stdout...)
			}
		}
	}

	slog.Info("nuclei pass 4: CVE scan (critical + high)", "scan_id", job.ScanID)
	cveResult, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Nuclei, cveArgs, nil, 20*time.Minute)
	if err != nil {
		slog.Warn("nuclei CVE pass failed", "error", err)
	} else {
		slog.Info("nuclei CVE pass complete", "bytes", len(cveResult.Stdout))
		allOutput = append(allOutput, cveResult.Stdout...)
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
