# sentryesc

A read-only Windows local privilege escalation enumerator, written in Go.

sentryesc scans a Windows host for common local privilege escalation
misconfigurations, the same category of issues tools like WinPEAS and
PowerUp look for, and reports each finding with a severity rating, an
explanation of the escalation path it enables, and guidance on how to fix
it. The goal is not simply to flag issues, but to make the underlying risk
understandable.

## Scope and Safety

This tool is strictly read-only. It does not modify services, write files,
escalate privileges, or take any exploitative action. Every check only
reads registry values, service configurations, and (in later checks)
file and ACL metadata.

Use it only on systems you own or are explicitly authorized to test.

## Checks Implemented

| Check | What It Finds | Severity |
|---|---|---|
| always-install-elevated | AlwaysInstallElevated registry misconfiguration allowing any user to install MSIs as SYSTEM | High |
| unquoted-service-path | Services with unquoted ImagePath values containing spaces | Medium |

Additional checks are planned, including weak service ACLs, scheduled
task permissions, autorun key ACLs, stored credentials, and token
privileges. See pkg/checks/ for the pattern used to add new ones.

## Building

Requires Go 1.22 or later. This tool only builds for Windows, since the
checks call Windows-only registry APIs and pkg/checks is entirely
behind a `//go:build windows` tag.

Building from Windows:

```
go mod tidy
go build -o sentryesc.exe ./cmd/sentryesc
```

Cross-compiling from macOS or Linux (produces a Windows binary; it cannot
run on the build machine itself):

```
GOOS=windows GOARCH=amd64 go mod tidy
GOOS=windows GOARCH=amd64 go build -o sentryesc.exe ./cmd/sentryesc
```

## Running

```
sentryesc.exe                    Human-readable report to stdout
sentryesc.exe -json              JSON output
sentryesc.exe -out report.txt    Write output to a file instead of stdout
```

Exit codes: 2 if findings were reported, 0 if the scan was clean, 1 on a
fatal error such as running on a non-Windows host.

## Architecture

cmd/sentryesc/ contains the CLI entry point and flag parsing.

pkg/checks/ contains one file per check. Each check implements the
Check interface (Name(), Description(), Run() ([]Finding, error)) and
registers itself in DefaultRegistry().

pkg/report/ handles output formatting for both JSON and
human-readable text.

pkg/winutil/ provides shared Windows API helpers for registry reads
and service enumeration, keeping individual checks focused on logic
rather than API boilerplate.

Adding a new check requires writing a file in pkg/checks/ that
implements the Check interface, then adding one line to
DefaultRegistry(). No other changes are needed.

## Desktop GUI

gui/ contains an optional desktop interface built with Wails. It calls
pkg/checks directly, the same scan logic the CLI uses, so there is no
subprocess or JSON parsing between the two. The CLI and GUI are two
front ends over one shared codebase.

Building and running the GUI requires the Wails CLI and Node.js in
addition to Go:

```
go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd gui
wails dev      Live development with hot reload
wails build    Produces a standalone .exe in gui/build/bin
```

## Why Go

Go cross-compiles to a single, dependency-free Windows binary from any
host operating system. It is also the language most modern offensive and
red team tooling is actually written in, making it a deliberate choice
rather than an academic one.
