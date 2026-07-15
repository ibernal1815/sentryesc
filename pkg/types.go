package checks

// Severity indicates how directly a finding leads to privilege escalation.
type Severity string

const (
	// SeverityInfo is informational — worth knowing, not exploitable alone.
	SeverityInfo Severity = "INFO"
	// SeverityLow is a weak signal that usually needs to be chained with something else.
	SeverityLow Severity = "LOW"
	// SeverityMedium is a real misconfiguration that plausibly leads to escalation.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh is a direct, reliable path to a higher-privileged context.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical is an immediate, trivial path to SYSTEM with no chaining required.
	SeverityCritical Severity = "CRITICAL"
)

// Finding is a single issue discovered by a check. Every field is meant to
// be readable on its own — someone should be able to read one Finding and
// understand what's wrong and why it matters without reading source code.
type Finding struct {
	Check       string   `json:"check"`       // which check produced this, e.g. "unquoted-service-path"
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`       // short summary, e.g. "Unquoted path in service ExampleSvc"
	Detail      string   `json:"detail"`      // the specific evidence: path, registry key, permission found
	Explanation string   `json:"explanation"` // why this matters / how it could be abused
	Remediation string   `json:"remediation"` // how to fix it
}

// Check is a single privilege-escalation vector scanner. Each check is
// independent, has no shared mutable state, and returns whatever it finds
// (an empty slice, not an error, if the host is simply clean).
type Check interface {
	// Name is a short, stable identifier used in Finding.Check and CLI output.
	Name() string
	// Description is a one-line summary shown in --help / report headers.
	Description() string
	// Run performs the check against the live host and returns findings.
	// An error means the check itself failed to execute (e.g. access denied
	// reading a registry key) — it does not mean "no findings."
	Run() ([]Finding, error)
}

// CheckError records a check that failed to execute (as opposed to a check
// that ran fine and simply found nothing).
type CheckError struct {
	Check string `json:"check"`
	Err   string `json:"error"`
}

// Results aggregates findings and execution errors across every check run
// in a single scan.
type Results struct {
	Findings []Finding    `json:"findings"`
	Errors   []CheckError `json:"errors,omitempty"`
}
