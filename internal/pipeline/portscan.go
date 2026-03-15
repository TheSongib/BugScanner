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

	// Scan only common web ports to minimise conntrack table pressure in Docker.
	// Top-1000 creates ~1000 conntrack entries that take ~60s to expire and break
	// subsequent httpx probes. Web-focused port list covers all practical HTTP targets.
	//
	// -s connect: use TCP connect scan instead of SYN scan. SYN scan requires
	// NET_RAW capability (raw sockets) which Docker containers don't have by default,
	// causing naabu to silently return 0 results. Connect scan is reliable in all
	// container environments at the cost of being slightly more detectable.
	result, err := s.deps.Runner.Run(ctx, s.deps.Config.Tools.Naabu, []string{
		"-list", "/dev/stdin",
		"-json",
		"-s", "connect",
		"-p", "80,443,8080,8443,8000,8888,3000,5000,4000,9000,9090,9443,4443,8008,8181,8800,7080,7443,6443,3001",
		"-rate", "300",
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
