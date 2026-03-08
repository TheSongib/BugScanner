package scope

import (
	"fmt"
	"regexp"
	"strings"
)

// Validator enforces bug bounty program scope rules.
// Every discovered asset must pass validation before being stored or scanned.
type Validator struct {
	inScope  []*regexp.Regexp
	outScope []*regexp.Regexp
}

// New creates a ScopeValidator from in-scope and out-of-scope pattern strings.
// Patterns are treated as regular expressions.
// Example in-scope: [".*\\.example\\.com$", ".*\\.example\\.org$"]
// Example out-of-scope: ["^prod\\.example\\.com$", ".*\\.internal\\.example\\.com$"]
func New(inPatterns, outPatterns []string) (*Validator, error) {
	v := &Validator{}

	for _, p := range inPatterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid in-scope pattern %q: %w", p, err)
		}
		v.inScope = append(v.inScope, r)
	}

	for _, p := range outPatterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid out-of-scope pattern %q: %w", p, err)
		}
		v.outScope = append(v.outScope, r)
	}

	return v, nil
}

// IsAllowed returns true only if the target matches at least one in-scope
// pattern AND matches zero out-of-scope patterns.
func (v *Validator) IsAllowed(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))

	if target == "" {
		return false
	}

	// Must match at least one in-scope pattern
	inMatch := false
	for _, r := range v.inScope {
		if r.MatchString(target) {
			inMatch = true
			break
		}
	}
	if !inMatch {
		return false
	}

	// Must not match any out-of-scope pattern
	for _, r := range v.outScope {
		if r.MatchString(target) {
			return false
		}
	}

	return true
}

// FilterAllowed returns only the targets that pass scope validation.
func (v *Validator) FilterAllowed(targets []string) []string {
	var allowed []string
	for _, t := range targets {
		if v.IsAllowed(t) {
			allowed = append(allowed, t)
		}
	}
	return allowed
}
