//go:build windows

package checks

import "github.com/ibernal/sentryesc/pkg/winutil"

// AlwaysInstallElevatedCheck detects the AlwaysInstallElevated
// misconfiguration, which lets any authenticated user install MSI
// packages with SYSTEM privileges.
type AlwaysInstallElevatedCheck struct{}

// NewAlwaysInstallElevatedCheck constructs the check.
func NewAlwaysInstallElevatedCheck() *AlwaysInstallElevatedCheck {
	return &AlwaysInstallElevatedCheck{}
}

func (c *AlwaysInstallElevatedCheck) Name() string { return "always-install-elevated" }

func (c *AlwaysInstallElevatedCheck) Description() string {
	return "Checks whether AlwaysInstallElevated is enabled, allowing any user to install MSI packages as SYSTEM"
}

// Run reads the HKLM AlwaysInstallElevated value. Note that Windows only
// honors this setting when the matching HKCU value is ALSO 1 - this check
// only has reliable access to HKLM, so it reports the HKLM state and is
// explicit in the finding that HKCU must be confirmed separately, rather
// than claiming a false positive or a false negative.
func (c *AlwaysInstallElevatedCheck) Run() ([]Finding, error) {
	const path = `SOFTWARE\Policies\Microsoft\Windows\Installer`
	const value = "AlwaysInstallElevated"

	v, ok := winutil.ReadDWORD(path, value)
	if !ok || v != 1 {
		return nil, nil
	}

	return []Finding{
		{
			Check:    c.Name(),
			Severity: SeverityHigh,
			Title:    "AlwaysInstallElevated is enabled (HKLM)",
			Detail: "HKLM\\" + path + "\\" + value + " = 1. This alone is not exploitable - " +
				"the matching HKCU value under the current user's hive must also be 1 for " +
				"Windows to honor it. This check only reads HKLM; confirm HKCU manually " +
				"(reg query HKCU\\" + path + " /v " + value + ").",
			Explanation: "When both HKLM and HKCU AlwaysInstallElevated values are 1, any " +
				"authenticated user can run 'msiexec /i malicious.msi' and have it install " +
				"with SYSTEM privileges regardless of their own permissions - a direct, " +
				"trivial path to full system compromise.",
			Remediation: "Set both registry values to 0 or remove them, via Group Policy: " +
				"Computer/User Configuration > Administrative Templates > Windows Components " +
				"> Windows Installer > 'Always install with elevated privileges' = Disabled.",
		},
	}, nil
}
