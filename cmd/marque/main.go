// Command marque is Marque's CLI: a thin wrapper over pkg/scope and
// pkg/audit. It contains no scope-matching or logging logic of its own —
// that all lives in the packages it imports.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
