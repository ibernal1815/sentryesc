//go:build windows

// Command sentryesc-gui is the desktop GUI for sentryesc, built with
// Wails. It calls pkg/checks directly rather than shelling out to
// the CLI binary, so there is no subprocess management or JSON parsing
// between the two - the GUI and CLI are two front ends over the same
// scan logic.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "sentryesc",
		Width:  1000,
		Height: 720,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
