package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// SubfinderResult represents a single subfinder JSON output line.
type SubfinderResult struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

// ParseSubfinder parses subfinder JSONL output and returns discovered subdomains.
func ParseSubfinder(data []byte) ([]SubfinderResult, error) {
	var results []SubfinderResult
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON format first
		var result SubfinderResult
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.Host != "" {
			host := strings.ToLower(result.Host)
			if !seen[host] {
				seen[host] = true
				result.Host = host
				results = append(results, result)
			}
			continue
		}

		// Fall back to plain text (one subdomain per line)
		host := strings.ToLower(line)
		if !seen[host] {
			seen[host] = true
			results = append(results, SubfinderResult{
				Host:   host,
				Source: "subfinder",
			})
		}
	}

	return results, scanner.Err()
}
