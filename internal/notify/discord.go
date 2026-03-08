package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var severityColors = map[string]int{
	"info":     0x3498DB, // blue
	"low":      0x2ECC71, // green
	"medium":   0xF39C12, // orange
	"high":     0xE74C3C, // red
	"critical": 0x8E44AD, // purple
}

type Discord struct {
	webhookURL string
	client     *http.Client
}

func NewDiscord(webhookURL string) *Discord {
	return &Discord{
		webhookURL: webhookURL,
		client:     &http.Client{},
	}
}

func (d *Discord) Name() string { return "discord" }

func (d *Discord) Send(ctx context.Context, event Event) error {
	color := severityColors[event.Severity]
	if color == 0 {
		color = 0x95A5A6 // gray default
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("[%s] %s", event.Severity, event.Title),
				"description": event.Details,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "Type", "value": event.Type, "inline": true},
					{"name": "Severity", "value": event.Severity, "inline": true},
				},
			},
		},
	}

	if event.URL != "" {
		embeds := payload["embeds"].([]map[string]interface{})
		embeds[0]["url"] = event.URL
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("send discord webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}
