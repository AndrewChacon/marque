package main

import "os"

// colorize wraps msg in the given ANSI color code, honoring NO_COLOR.
// Shared by validate's expired-window warning and proxy's live
// decision stream so there's one place that knows about ANSI codes
// and the NO_COLOR convention, not two.
func colorize(ansiCode, msg string) string {
	if os.Getenv("NO_COLOR") != "" {
		return msg
	}
	return "\x1b[" + ansiCode + "m" + msg + "\x1b[0m"
}

const (
	colorRed    = "31"
	colorGreen  = "32"
	colorYellow = "33"
)
