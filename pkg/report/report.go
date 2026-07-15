// Package report formats checks.Results for output, either as JSON for
// machine consumption or as a human-readable text report grouped by
// severity.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ibernal/sentryesc/pkg/checks"
)

// WriteJSON writes results as indented JSON.
func WriteJSON(w io.Writer, results checks.Results) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// severityOrder defines the display order, most urgent first.
var severityOrder = []checks.Severity{
	checks.SeverityCritical,
	checks.SeverityHigh,
	checks.SeverityMedium,
	checks.SeverityLow,
	checks.SeverityInfo,
}

// WriteHuman writes a readable report grouped by severity, most urgent
// first. It never returns an error - fmt.Fprint failures on a report
// writer aren't actionable for the caller, so this matches main.go's
// current call site, which doesn't check a return value here.
func WriteHuman(w io.Writer, results checks.Results) {
	fmt.Fprintf(w, "sentryesc scan results - %d finding(s)\n\n", len(results.Findings))

	if len(results.Findings) == 0 {
		fmt.Fprintln(w, "No findings from the checks that ran successfully.")
	}

	for _, sev := range severityOrder {
		var group []checks.Finding
		for _, f := range results.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}

		fmt.Fprintf(w, "=== %s (%d) ===\n", sev, len(group))
		for _, f := range group {
			fmt.Fprintf(w, "\n[%s] %s\n", f.Check, f.Title)
			fmt.Fprintf(w, "  Detail:      %s\n", f.Detail)
			fmt.Fprintf(w, "  Why it matters: %s\n", f.Explanation)
			if f.Remediation != "" {
				fmt.Fprintf(w, "  Fix:         %s\n", f.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	if len(results.Errors) > 0 {
		fmt.Fprintf(w, "=== Checks that failed to run (%d) ===\n", len(results.Errors))
		for _, e := range results.Errors {
			fmt.Fprintf(w, "  - %s: %s\n", e.Check, e.Err)
		}
	}
}
