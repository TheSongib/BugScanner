package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var severityEmoji = map[string]string{
	"info":     ":information_source:",
	"low":      ":large_green_circle:",
	"medium":   ":large_orange_circle:",
	"high":     ":red_circle:",
	"critical": ":rotating_light:",
}

type Slack struct {
	webhookURL string
	client     *http.Client
}

func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client:     &http.Client{},
	}
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Send(ctx context.Context, event Event) error {
	emoji := severityEmoji[event.Severity]
	if emoji == "" {
		emoji = ":question:"
	}

	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("%s [%s] %s", emoji, event.Severity, event.Title),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": event.Details,
				},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Type:* %s | *Scan:* %s", event.Type, event.ScanID)},
				},
			},
		},
	}

	if event.URL != "" {
		blocks := payload["blocks"].([]map[string]interface{})
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*URL:* %s", event.URL),
			},
		})
		payload["blocks"] = blocks
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}
