package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/parser"
)

// DiscoveryStage handles subdomain enumeration using subfinder, amass, and shuffledns.
type DiscoveryStage struct {
	deps *Deps
}

func NewDiscoveryStage(deps *Deps) *DiscoveryStage {
	return &DiscoveryStage{deps: deps}
}

func (s *DiscoveryStage) Name() string { return StageDiscovery }

func (s *DiscoveryStage) Run(ctx context.Context, job broker.Job) (int, error) {
	var payload broker.DiscoveryPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return 0, fmt.Errorf("unmarshal discovery payload: %w", err)
	}

	slog.Info("starting asset discovery", "domain", payload.Domain, "scan_id", job.ScanID)

	// Create scope validator
	sv, err := NewScopeValidator(payload.ScopeIn, payload.ScopeOut)
	if err != nil {
		return 0, fmt.Errorf("create scope validator: %w", err)
	}

	// Create domain record
	domain, err := s.deps.DomainRepo.Create(ctx, job.ScanID, payload.Domain)
	if err != nil {
		return 0, fmt.Errorf("create domain: %w", err)
	}

	// Run discovery tools in parallel
	type result struct {
		subdomains []string
		source     string
		err        error
	}

	var wg sync.WaitGroup
	results := make(chan result, 3)

	// Subfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := s.runSubfinder(ctx, payload.Domain)
		results <- result{subdomains: subs, source: "subfinder", err: err}
	}()

	// Amass
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := s.runAmass(ctx, payload.Domain)
		results <- result{subdomains: subs, source: "amass", err: err}
	}()

	// ShuffleDNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := s.runShuffleDNS(ctx, payload.Domain)
		results <- result{subdomains: subs, source: "shuffledns", err: err}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	// Merge and dedup results
	seen := make(map[string]string) // subdomain -> source
	for r := range results {
		if r.err != nil {
			slog.Warn("discovery tool failed", "source", r.source, "error", r.err)
			continue
		}
		for _, sub := range r.subdomains {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if sub == "" {
				continue
			}
			// Scope check before storing
			if !sv.IsAllowed(sub) {
				slog.Debug("out of scope subdomain filtered", "subdomain", sub)
				continue
			}
			if _, exists := seen[sub]; !exists {
				seen[sub] = r.source
			}
		}
	}

	// Store subdomains
	subs := make([]struct {
		Name   string
		Source string
	}, 0, len(seen))
	for name, source := range seen {
		subs = append(subs, struct {
			Name   string
			Source string
		}{Name: name, Source: source})
	}

	count, err := s.deps.SubRepo.BulkUpsert(ctx, domain.ID, subs)
	if err != nil {
		return 0, fmt.Errorf("store subdomains: %w", err)
	}

	slog.Info("discovery complete", "domain", payload.Domain, "subdomains_found", count)

	// Always include the target domain itself — subfinder only finds
	// *subdomains* of the domain, so a leaf hostname like "testphp.vulnweb.com"
	// would otherwise be missed entirely.
	if _, exists := seen[payload.Domain]; !exists {
		seen[payload.Domain] = "self"
	}

	// Publish next stage: port scan
	targets := make([]string, 0, len(seen))
	for sub := range seen {
		targets = append(targets, sub)
	}

	if len(targets) > 0 {
		err = s.deps.Broker.PublishToStage(ctx, broker.QueuePortScan, job.ScanID, broker.PortScanPayload{
			Targets: targets,
		})
		if err != nil {
			return count, fmt.Errorf("publish portscan job: %w", err)
		}
	} else {
		// No targets at all — mark scan complete so it doesn't hang forever.
		slog.Info("no targets discovered, completing scan", "scan_id", job.ScanID)
		s.deps.ScanRepo.UpdateStatus(ctx, job.ScanID, database.ScanStatusCompleted)
	}

	return count, nil
}

func (s *DiscoveryStage) runSubfinder(ctx context.Context, domain string) ([]string, error) {
	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Subfinder, []string{
		"-d", domain,
		"-silent",
		"-json",
	}, nil)
	if err != nil {
		return nil, err
	}

	parsed, err := parser.ParseSubfinder(result.Stdout)
	if err != nil {
		return nil, err
	}

	subs := make([]string, len(parsed))
	for i, p := range parsed {
		subs[i] = p.Host
	}
	return subs, nil
}

func (s *DiscoveryStage) runAmass(ctx context.Context, domain string) ([]string, error) {
	result, err := s.deps.Runner.RunWithTimeout(ctx, s.deps.Config.Tools.Amass, []string{
		"enum",
		"-passive",
		"-d", domain,
		"-json", "/dev/stdout",
	}, nil, 15*time.Minute)
	if err != nil {
		return nil, err
	}

	parsed, err := parser.ParseAmass(result.Stdout)
	if err != nil {
		return nil, err
	}

	subs := make([]string, len(parsed))
	for i, p := range parsed {
		subs[i] = p.Name
	}
	return subs, nil
}

func (s *DiscoveryStage) runShuffleDNS(ctx context.Context, domain string) ([]string, error) {
	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.ShuffleDNS, []string{
		"-d", domain,
		"-w", "/usr/share/wordlists/dns.txt",
		"-r", "/usr/share/wordlists/resolvers.txt",
		"-silent",
	}, nil)
	if err != nil {
		return nil, err
	}

	// ShuffleDNS outputs plain text, one subdomain per line
	parsed, err := parser.ParseSubfinder(result.Stdout) // same format
	if err != nil {
		return nil, err
	}

	subs := make([]string, len(parsed))
	for i, p := range parsed {
		subs[i] = p.Host
	}
	return subs, nil
}
