//go:build windows

// Package winutil wraps golang.org/x/sys/windows calls needed by multiple
// checks so individual check files stay focused on logic rather than
// Windows API boilerplate. Every function here is read-only.
package winutil

import (
	"golang.org/x/sys/windows/registry"
)

// ReadDWORD reads a DWORD value under HKEY_LOCAL_MACHINE. ok=false means
// the key or value doesn't exist, which is a normal outcome for most of
// these checks (it means the misconfiguration simply isn't present) and
// is not treated as an error.
func ReadDWORD(path, valueName string) (value uint32, ok bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// ReadString reads a string value under HKEY_LOCAL_MACHINE.
func ReadString(path, valueName string) (value string, ok bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()

	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return "", false
	}
	return v, true
}

// SubKeyNames lists the immediate subkey names under an HKLM path - used
// to enumerate all services under SYSTEM\CurrentControlSet\Services.
func SubKeyNames(path string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	return k.ReadSubKeyNames(-1)
}
