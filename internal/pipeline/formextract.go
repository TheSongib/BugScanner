package pipeline

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// formEntry holds the parsed data from a single HTML <form> element.
type formEntry struct {
	Action string
	Method string
	Fields []string // input/textarea/select name attributes
}

// parseFormsFromURLs fetches each URL, parses HTML forms, and returns synthetic
// katana-format JSONL lines for POST forms. These lines are fed to nuclei DAST
// via -im jsonl so it can fuzz POST body parameters directly.
func parseFormsFromURLs(urls []string) []string {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	seen := make(map[string]bool)
	var lines []string

	for _, rawURL := range urls {
		// Only process HTML pages — skip assets.
		if isAsset(rawURL) {
			continue
		}

		forms, err := fetchAndParseForms(client, rawURL)
		if err != nil {
			slog.Debug("form parse failed", "url", rawURL, "error", err)
			continue
		}

		for _, f := range forms {
			if !strings.EqualFold(f.Method, "POST") || len(f.Fields) == 0 {
				continue
			}

			action := resolveURL(rawURL, f.Action)
			if action == "" {
				continue
			}

			// Build a URL-encoded body with empty placeholder values so nuclei
			// knows which parameters exist and will fuzz each one.
			body := buildFormBody(f.Fields)
			key := action + "|" + body
			if seen[key] {
				continue
			}
			seen[key] = true

			line := buildKatanaFormLine(action, body)
			if line != "" {
				lines = append(lines, line)
				slog.Info("discovered POST form", "action", action, "fields", f.Fields)
			}
		}
	}

	return lines
}

// fetchAndParseForms GETs the URL and returns all <form> elements found.
func fetchAndParseForms(client *http.Client, rawURL string) ([]formEntry, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "html") && ct != "" {
		return nil, fmt.Errorf("non-HTML content-type: %s", ct)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, err
	}

	return extractForms(doc), nil
}

// extractForms walks the HTML node tree and collects form data.
func extractForms(n *html.Node) []formEntry {
	var forms []formEntry
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			f := parseFormNode(node)
			forms = append(forms, f)
			return // don't recurse into nested forms
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return forms
}

// parseFormNode extracts action, method, and field names from a <form> node.
func parseFormNode(formNode *html.Node) formEntry {
	f := formEntry{Method: "GET"}

	for _, attr := range formNode.Attr {
		switch strings.ToLower(attr.Key) {
		case "action":
			f.Action = attr.Val
		case "method":
			f.Method = strings.ToUpper(attr.Val)
		}
	}

	var walkFields func(*html.Node)
	walkFields = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select":
				name := attrVal(n, "name")
				inputType := attrVal(n, "type")
				// Skip submit buttons and hidden fields — they're not fuzzing targets.
				if name != "" && inputType != "submit" && inputType != "button" && inputType != "hidden" {
					f.Fields = append(f.Fields, name)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFields(c)
		}
	}
	walkFields(formNode)

	return f
}

// buildFormBody constructs a URL-encoded body string with empty values.
func buildFormBody(fields []string) string {
	vals := url.Values{}
	for _, f := range fields {
		vals.Set(f, "")
	}
	return vals.Encode()
}

// buildKatanaFormLine serialises a POST form target into the katana JSONL format
// that nuclei DAST understands when reading with -im jsonl.
func buildKatanaFormLine(action, body string) string {
	parsed, err := url.Parse(action)
	if err != nil {
		return ""
	}

	rawReq := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s",
		parsed.RequestURI(), parsed.Host, body,
	)

	entry := map[string]any{
		"request": map[string]any{
			"method":   "POST",
			"endpoint": action,
			"body":     body,
			"raw":      rawReq,
			"tag":      "form",
		},
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	return string(b)
}

// resolveURL resolves a form action (possibly relative) against the page URL.
func resolveURL(pageURL, action string) string {
	if action == "" {
		return pageURL
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(action)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// isAsset returns true for URLs that are unlikely to contain HTML forms.
func isAsset(u string) bool {
	path := u
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		path = parsed.Path
	}

	lowerPath := strings.ToLower(path)
	for _, ext := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip"} {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// attrVal finds the value of an attribute on an HTML node.
func attrVal(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}
