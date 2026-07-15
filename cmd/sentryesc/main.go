// Command sentryesc scans a Windows host for common local privilege
// escalation vectors and reports findings with severity and explanation.
//
// It is intended for use on systems you own or are authorized to test.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/ibernal/sentryesc/pkg/checks"
	"github.com/ibernal/sentryesc/pkg/report"
)

func main() {
	jsonOut := flag.Bool("json", false, "output findings as JSON instead of a human-readable report")
	outFile := flag.String("out", "", "write output to file instead of stdout")
	flag.Parse()

	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "sentryesc: this tool only runs on Windows (it reads Windows services, registry, and ACLs)")
		os.Exit(1)
	}

	registry := checks.DefaultRegistry()
	results := registry.RunAll()

	var out *os.File = os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentryesc: could not create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	if *jsonOut {
		if err := report.WriteJSON(out, results); err != nil {
			fmt.Fprintf(os.Stderr, "sentryesc: error writing JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	report.WriteHuman(out, results)
}
