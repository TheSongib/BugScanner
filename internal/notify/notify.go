package notify

import (
	"context"
	"log/slog"

	"github.com/brandon/bugscanner/internal/config"
)

// Severity levels for notification filtering.
var severityOrder = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Event represents a notification event.
type Event struct {
	Type     string `json:"type"`     // new_vuln, scan_complete, scan_error
	Severity string `json:"severity"` // info, low, medium, high, critical
	Title    string `json:"title"`
	Details  string `json:"details"`
	URL      string `json:"url,omitempty"`
	ScanID   string `json:"scan_id,omitempty"`
}

// Notifier sends notifications to external services.
type Notifier interface {
	Send(ctx context.Context, event Event) error
	Name() string
}

// Dispatcher fans out events to multiple notifiers with severity filtering.
type Dispatcher struct {
	notifiers   []Notifier
	minSeverity int
}

// NewDispatcher creates a dispatcher from the config, registering all configured notifiers.
func NewDispatcher(cfg config.NotifyConfig) *Dispatcher {
	d := &Dispatcher{
		minSeverity: severityOrder[cfg.MinSeverity],
	}

	if cfg.DiscordWebhookURL != "" {
		d.notifiers = append(d.notifiers, NewDiscord(cfg.DiscordWebhookURL))
	}

	if cfg.SlackWebhookURL != "" {
		d.notifiers = append(d.notifiers, NewSlack(cfg.SlackWebhookURL))
	}

	return d
}

// Send dispatches an event to all registered notifiers if it meets the minimum severity.
func (d *Dispatcher) Send(ctx context.Context, event Event) {
	eventSeverity := severityOrder[event.Severity]
	if eventSeverity < d.minSeverity {
		return
	}

	for _, n := range d.notifiers {
		if err := n.Send(ctx, event); err != nil {
			slog.Error("notification failed",
				"notifier", n.Name(),
				"error", err,
				"event_type", event.Type,
			)
		}
	}
}
