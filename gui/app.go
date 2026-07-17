//go:build windows

package main

import (
	"context"

	"github.com/ibernal/sentryesc/pkg/checks"
)

// App holds application state and exposes methods that Wails binds to
// the frontend. Any exported method on App becomes callable from
// JavaScript as window.go.main.App.<MethodName>(...).
type App struct {
	ctx context.Context
}

// NewApp constructs the app.
func NewApp() *App {
	return &App{}
}

// startup is called by Wails once the frontend is ready. Kept for future
// use (e.g. emitting startup events) - currently just stores the context.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Scan runs every registered check and returns the aggregated results.
// Wails automatically marshals the returned struct to JSON for the
// frontend, using the same checks.Results type (and json tags) the CLI's
// -json flag produces - so the GUI and CLI JSON output are identical in
// shape.
func (a *App) Scan() checks.Results {
	registry := checks.DefaultRegistry()
	return registry.RunAll()
}
