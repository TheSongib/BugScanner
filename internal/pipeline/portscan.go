package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/brandon/bugscanner/internal/broker"
	"github.com/brandon/bugscanner/internal/database"
	"github.com/brandon/bugscanner/internal/parser"
)

// PortScanStage handles port scanning using naabu.
type PortScanStage struct {
	deps *Deps
}

func NewPortScanStage(deps *Deps) *PortScanStage {
	return &PortScanStage{deps: deps}
}

func (s *PortScanStage) Name() string { return StagePortScan }

func (s *PortScanStage) Run(ctx context.Context, job broker.Job) (int, error) {
	var payload broker.PortScanPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return 0, fmt.Errorf("unmarshal portscan payload: %w", err)
	}

	slog.Info("starting port scan", "targets", len(payload.Targets), "scan_id", job.ScanID)

	// Create a temp input for naabu (pass targets via stdin)
	targetList := strings.Join(payload.Targets, "\n")

	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Naabu, []string{
		"-list", "/dev/stdin",
		"-json",
		"-top-ports", "1000",
		"-rate", "1000",
		"-silent",
	}, strings.NewReader(targetList))
	if err != nil {
		return 0, fmt.Errorf("run naabu: %w", err)
	}

	hostPorts, err := parser.ParseNaabu(result.Stdout)
	if err != nil {
		return 0, fmt.Errorf("parse naabu output: %w", err)
	}

	slog.Info("port scan complete", "open_ports_found", len(hostPorts))

	// Store results and build next stage input
	httpTargets := make([]string, 0, len(hostPorts))

	for _, hp := range hostPorts {
		// Store IP and port in database
		ip, err := s.deps.IPRepo.Upsert(ctx, hp.IP, false, "")
		if err != nil {
			slog.Warn("failed to store IP", "ip", hp.IP, "error", err)
			continue
		}

		_, err = s.deps.PortRepo.Upsert(ctx, ip.ID, hp.Port, hp.Protocol, "")
		if err != nil {
			slog.Warn("failed to store port", "ip", hp.IP, "port", hp.Port, "error", err)
			continue
		}

		// Build URL for httpx — format as scheme://host so httpx doesn't
		// have to guess the protocol. Non-standard ports get both schemes.
		host := hp.Host
		if host == "" {
			host = hp.IP
		}
		switch hp.Port {
		case 443, 8443:
			httpTargets = append(httpTargets, fmt.Sprintf("https://%s", host))
		case 80:
			httpTargets = append(httpTargets, fmt.Sprintf("http://%s", host))
		default:
			httpTargets = append(httpTargets, fmt.Sprintf("http://%s:%d", host, hp.Port))
			httpTargets = append(httpTargets, fmt.Sprintf("https://%s:%d", host, hp.Port))
		}
	}

	// Publish next stage: HTTP probing
	if len(httpTargets) > 0 {
		err = s.deps.Broker.PublishToStage(ctx, broker.QueueHTTPProbe, job.ScanID, broker.HTTPProbePayload{
			HostPorts: httpTargets,
		})
		if err != nil {
			return len(hostPorts), fmt.Errorf("publish httpprobe job: %w", err)
		}
	} else {
		// No open ports found — pipeline ends here, mark scan complete.
		slog.Info("no open ports found, completing scan", "scan_id", job.ScanID)
		s.deps.ScanRepo.UpdateStatus(ctx, job.ScanID, database.ScanStatusCompleted)
	}

	return len(hostPorts), nil
}
