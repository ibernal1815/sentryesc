//go:build windows

package checks

import (
	"fmt"
	"strings"

	"github.com/ibernal/sentryesc/pkg/winutil"
)

// UnquotedServicePathCheck finds services whose ImagePath contains a space
// but is not wrapped in quotes. Windows resolves such a path by trying
// each space-delimited segment as a candidate executable, in order - if an
// attacker can write a file to one of the earlier candidate locations,
// their binary runs instead of the intended one, at whatever privilege
// the service runs as (frequently SYSTEM).
type UnquotedServicePathCheck struct{}

// NewUnquotedServicePathCheck constructs the check.
func NewUnquotedServicePathCheck() *UnquotedServicePathCheck {
	return &UnquotedServicePathCheck{}
}

func (c *UnquotedServicePathCheck) Name() string { return "unquoted-service-path" }

func (c *UnquotedServicePathCheck) Description() string {
	return "Finds services with unquoted ImagePath values containing spaces, a classic local privesc vector"
}

const servicesKey = `SYSTEM\CurrentControlSet\Services`

func (c *UnquotedServicePathCheck) Run() ([]Finding, error) {
	names, err := winutil.SubKeyNames(servicesKey)
	if err != nil {
		return nil, fmt.Errorf("enumerating services: %w", err)
	}

	var findings []Finding
	for _, svc := range names {
		path, ok := winutil.ReadString(servicesKey+`\`+svc, "ImagePath")
		if !ok || path == "" {
			continue
		}
		if isVulnerableUnquotedPath(path) {
			findings = append(findings, Finding{
				Check:    c.Name(),
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("Unquoted service path: %s", svc),
				Detail: fmt.Sprintf("Service %q has ImagePath = %q. This path contains a "+
					"space and is not quoted.", svc, path),
				Explanation: "Windows will try each space-delimited path segment in order " +
					"as a candidate executable before falling back to the full intended " +
					"path. If any writable directory exists among those earlier candidate " +
					"locations, an attacker can drop a binary there that runs at this " +
					"service's privilege level on next start - often SYSTEM. This finding " +
					"alone does not confirm exploitability; it confirms the path shape that " +
					"makes it possible. Verify write access to the candidate directories " +
					"before treating this as a confirmed finding.",
				Remediation: fmt.Sprintf("Wrap the executable path in quotes, e.g. update "+
					"ImagePath for %q to start with a quoted path segment.", svc),
			})
		}
	}
	return findings, nil
}

// isVulnerableUnquotedPath reports whether path is the classic vulnerable
// shape: contains a space before the .exe extension, and is not already
// quoted. Write-access confirmation for the candidate directories is a
// deliberately separate, manual step (see Explanation above) - it isn't
// automated by this check, since doing that safely requires ACL analysis
// this check doesn't yet perform.
func isVulnerableUnquotedPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, `"`) {
		return false // already quoted
	}

	// Only the portion up to the first recognized executable extension
	// matters - arguments after the .exe are irrelevant to this check.
	lower := strings.ToLower(trimmed)
	extIdx := strings.Index(lower, ".exe")
	if extIdx == -1 {
		return false // not an .exe target (e.g. svchost -k style, driver, etc.)
	}

	execPortion := trimmed[:extIdx+len(".exe")]
	return strings.Contains(execPortion, " ")
}
