package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// NaabuResult represents a single naabu JSON output line.
type NaabuResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// HostPort is a simplified host:port result.
type HostPort struct {
	Host     string
	IP       string
	Port     int
	Protocol string
}

// ParseNaabu parses naabu JSON output and returns discovered host:port pairs.
func ParseNaabu(data []byte) ([]HostPort, error) {
	var results []HostPort
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON format
		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.Port > 0 {
			key := fmt.Sprintf("%s:%s:%d", result.Host, result.IP, result.Port)
			if !seen[key] {
				seen[key] = true
				protocol := result.Protocol
				if protocol == "" {
					protocol = "tcp"
				}
				results = append(results, HostPort{
					Host:     result.Host,
					IP:       result.IP,
					Port:     result.Port,
					Protocol: protocol,
				})
			}
			continue
		}

		// Plain text: host:port
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				key := fmt.Sprintf("%s:%d", parts[0], port)
				if !seen[key] {
					seen[key] = true
					results = append(results, HostPort{
						Host:     parts[0],
						Port:     port,
						Protocol: "tcp",
					})
				}
			}
		}
	}

	return results, scanner.Err()
}
