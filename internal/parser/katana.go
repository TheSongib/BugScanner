package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// KatanaResult represents a single katana JSON output line.
type KatanaResult struct {
	Request  KatanaRequest  `json:"request"`
	Response KatanaResponse `json:"response,omitempty"`
}

type KatanaRequest struct {
	Method    string `json:"method"`
	Endpoint  string `json:"endpoint"`
	Tag       string `json:"tag"`
	Attribute string `json:"attribute"`
	Source    string `json:"source"`
}

type KatanaResponse struct {
	StatusCode int `json:"status_code"`
}

// CrawlURL is a simplified crawl result.
type CrawlURL struct {
	URL       string
	Method    string
	SourceURL string
}

// ParseKatana parses katana JSON output and returns discovered URLs.
func ParseKatana(data []byte) ([]CrawlURL, error) {
	var results []CrawlURL
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON format
		var result KatanaResult
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.Request.Endpoint != "" {
			method := result.Request.Method
			if method == "" {
				method = "GET"
			}
			key := method + ":" + result.Request.Endpoint
			if !seen[key] {
				seen[key] = true
				results = append(results, CrawlURL{
					URL:       result.Request.Endpoint,
					Method:    method,
					SourceURL: result.Request.Source,
				})
			}
			continue
		}

		// Plain text: just URLs
		if strings.HasPrefix(line, "http") {
			if !seen["GET:"+line] {
				seen["GET:"+line] = true
				results = append(results, CrawlURL{
					URL:    line,
					Method: "GET",
				})
			}
		}
	}

	return results, scanner.Err()
}
