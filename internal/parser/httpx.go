package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
)

// HTTPXResult represents a single httpx JSON output line.
type HTTPXResult struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	ContentLength int64    `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	WebServer     string   `json:"webserver"`
	Technologies  []string `json:"tech"`
	CDNName       string   `json:"cdn_name"`
	CDN           bool     `json:"cdn"`
	ResponseTime  string   `json:"response_time"`
	Method        string   `json:"method"`
	FinalURL      string   `json:"final_url"`
	Failed        bool     `json:"failed"`
}

// ParseHTTPX parses httpx JSON output and returns HTTP probe results.
func ParseHTTPX(data []byte) ([]HTTPXResult, error) {
	var results []HTTPXResult
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Increase buffer size for long lines
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result HTTPXResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			slog.Warn("httpx: failed to parse JSON line", "line", line, "error", err)
			continue
		}

		// Use input as fallback URL — some httpx versions omit url when probing fails
		// but still emit a JSON record.
		if result.URL == "" {
			result.URL = result.Input
		}

		if result.Failed || result.URL == "" {
			slog.Debug("httpx: skipping result", "url", result.URL, "input", result.Input, "failed", result.Failed)
			continue
		}

		if !seen[result.URL] {
			seen[result.URL] = true
			results = append(results, result)
		}
	}

	return results, scanner.Err()
}
