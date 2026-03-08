package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// AmassResult represents a single amass JSON output entry.
type AmassResult struct {
	Name      string   `json:"name"`
	Domain    string   `json:"domain"`
	Addresses []AmassAddress `json:"addresses,omitempty"`
	Sources   []string `json:"sources,omitempty"`
}

type AmassAddress struct {
	IP   string `json:"ip"`
	CIDR string `json:"cidr"`
	ASN  int    `json:"asn"`
	Desc string `json:"desc"`
}

// ParseAmass parses amass JSON output and returns discovered subdomains.
func ParseAmass(data []byte) ([]AmassResult, error) {
	var results []AmassResult
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result AmassResult
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.Name != "" {
			name := strings.ToLower(result.Name)
			if !seen[name] {
				seen[name] = true
				result.Name = name
				results = append(results, result)
			}
			continue
		}

		// Plain text fallback
		host := strings.ToLower(line)
		if !seen[host] {
			seen[host] = true
			results = append(results, AmassResult{
				Name:   host,
				Sources: []string{"amass"},
			})
		}
	}

	return results, scanner.Err()
}
