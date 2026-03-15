package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Job represents a unit of work passed through the pipeline.
type Job struct {
	ID      string          `json:"id"`
	ScanID  string          `json:"scan_id"`
	Stage   string          `json:"stage"`
	Payload json.RawMessage `json:"payload"`
}

// DiscoveryPayload is the payload for the asset discovery stage.
type DiscoveryPayload struct {
	Domain   string   `json:"domain"`
	ScopeIn  []string `json:"scope_in"`
	ScopeOut []string `json:"scope_out"`
}

// PortScanPayload is the payload for the port scanning stage.
type PortScanPayload struct {
	Targets []string `json:"targets"` // list of IPs or hostnames
}

// HTTPProbePayload is the payload for the HTTP probing stage.
type HTTPProbePayload struct {
	HostPorts []string `json:"host_ports"` // host:port pairs
}

// CrawlPayload is the payload for the crawling stage.
type CrawlPayload struct {
	URLs []string `json:"urls"` // live HTTP URLs
}

// VulnScanPayload is the payload for the vulnerability scanning stage.
type VulnScanPayload struct {
	URLs         []string `json:"urls"`
	FormTargets  []string `json:"form_targets,omitempty"`  // raw katana JSONL lines for POST form fuzzing
	Technologies []string `json:"technologies,omitempty"` // for template selection
}

// Publish sends a job to the specified queue.
func (b *Broker) Publish(ctx context.Context, queueName string, job Job) error {
	body, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}

	ch := b.Channel()
	return ch.PublishWithContext(
		ctx,
		"",        // default exchange
		queueName, // routing key = queue name
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         body,
			Timestamp:    time.Now(),
			MessageId:    job.ID,
		},
	)
}

// PublishToStage is a convenience method that sets the job's stage and publishes.
func (b *Broker) PublishToStage(ctx context.Context, queueName string, scanID string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	job := Job{
		ID:      fmt.Sprintf("%s-%s-%d", scanID, queueName, time.Now().UnixNano()),
		ScanID:  scanID,
		Stage:   queueName,
		Payload: payloadBytes,
	}

	return b.Publish(ctx, queueName, job)
}
