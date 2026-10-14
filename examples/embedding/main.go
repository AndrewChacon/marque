// Command embedding demonstrates using pkg/scope as a plain Go
// library, with no CLI, proxy, or audit log involved. A real caller
// would be something like an autonomous agent's tool-use loop, asking
// "am I allowed to touch this host?" before every outbound action.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AndrewChacon/red-marque/pkg/scope"
)

// targets stands in for whatever an agent loop would actually be
// iterating over — URLs it's about to fetch, hosts it's about to
// scan, etc. Hardcoded here since the point is showing the Check
// call, not building a real agent.
var targets = []string{
	"10.0.1.5",
	"10.0.5.9",
	"api.example-corp.test",
	"admin.example-corp.test",
	"evil.example",
}

func main() {
	s, err := scope.Load(scopeFilePath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading scope:", err)
		os.Exit(1)
	}

	fmt.Printf("engagement: %s (%s)\n\n", s.Name, s.Client)

	denied := 0
	for _, target := range targets {
		d := s.CheckHost(target)
		status := "ALLOW"
		if !d.Allowed {
			status = "BLOCK"
			denied++
		}
		fmt.Printf("%-6s %-25s %s\n", status, target, d.Reason)
	}

	if denied > 0 {
		fmt.Printf("\n%d of %d targets were out of scope.\n", denied, len(targets))
	}
}

// scopeFilePath resolves scope.yaml relative to this source file
// rather than the process's working directory, so `go run
// ./examples/embedding` works regardless of where it's invoked from.
func scopeFilePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "scope.yaml")
}
