package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// NucleiResult represents a single nuclei JSON output line.
type NucleiResult struct {
	Template     string       `json:"template"`
	TemplateURL  string       `json:"template-url"`
	TemplateID   string       `json:"template-id"`
	TemplatePath string       `json:"template-path"`
	Info         NucleiInfo   `json:"info"`
	Type         string       `json:"type"`
	Host         string       `json:"host"`
	MatchedURL   string       `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	IP           string       `json:"ip"`
	Timestamp    string       `json:"timestamp"`
	CurlCommand  string       `json:"curl-command"`
	MatcherName  string       `json:"matcher-name"`
	MatchedLine  string       `json:"matched-line"`
}

type NucleiInfo struct {
	Name        string       `json:"name"`
	Author      []string     `json:"author"`
	Tags        []string     `json:"tags"`
	Description string       `json:"description"`
	Reference   []string     `json:"reference"`
	Severity    string       `json:"severity"`
	Metadata    NucleiMeta   `json:"metadata,omitempty"`
}

type NucleiMeta struct {
	MaxRequest int    `json:"max-request"`
	Verified   bool   `json:"verified"`
	ShodanQuery string `json:"shodan-query,omitempty"`
}

// VulnFinding is a simplified vulnerability finding.
type VulnFinding struct {
	TemplateID   string
	TemplateName string
	Severity     string
	MatchedURL   string
	MatchedAt    string
	Host         string
	IP           string
	CurlCommand  string
	Reference    []string
	Tags         []string
	Description  string
	ExtractedData []string
}

// ParseNuclei parses nuclei JSON output and returns vulnerability findings.
func ParseNuclei(data []byte) ([]VulnFinding, error) {
	var results []VulnFinding
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// 10 MB buffer — nuclei findings with large extracted payloads or many results
	// can easily exceed the default 64 KB limit and the previous 1 MB cap, causing
	// scanner.Scan() to return false mid-output and silently drop remaining findings.
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		if result.TemplateID == "" || result.MatchedURL == "" {
			continue
		}

		// Dedup by template + matched URL
		key := result.TemplateID + ":" + result.MatchedURL
		if seen[key] {
			continue
		}
		seen[key] = true

		results = append(results, VulnFinding{
			TemplateID:    result.TemplateID,
			TemplateName:  result.Info.Name,
			Severity:      strings.ToLower(result.Info.Severity),
			MatchedURL:    result.MatchedURL,
			MatchedAt:     result.MatchedLine,
			Host:          result.Host,
			IP:            result.IP,
			CurlCommand:   result.CurlCommand,
			Reference:     result.Info.Reference,
			Tags:          result.Info.Tags,
			Description:   result.Info.Description,
			ExtractedData: result.ExtractedResults,
		})
	}

	return results, scanner.Err()
}
