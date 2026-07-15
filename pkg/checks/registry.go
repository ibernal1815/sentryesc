//go:build windows

package checks

// Registry holds a set of checks and runs them together.
type Registry struct {
	checks []Check
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Add registers a check to be run by RunAll.
func (r *Registry) Add(c Check) {
	r.checks = append(r.checks, c)
}

// RunAll runs every registered check and aggregates results. A check that
// returns an error is recorded in Results.Errors and does not stop the
// remaining checks from running.
func (r *Registry) RunAll() Results {
	var res Results
	for _, c := range r.checks {
		findings, err := c.Run()
		if err != nil {
			res.Errors = append(res.Errors, CheckError{Check: c.Name(), Err: err.Error()})
			continue
		}
		res.Findings = append(res.Findings, findings...)
	}
	return res
}

// DefaultRegistry returns a Registry pre-loaded with every check this tool
// ships. This is the single place that needs updating when a new check is
// added - main.go and everything else stays untouched.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Add(NewAlwaysInstallElevatedCheck())
	r.Add(NewUnquotedServicePathCheck())
	return r
}
