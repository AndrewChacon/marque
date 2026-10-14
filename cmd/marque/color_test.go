package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColorize(t *testing.T) {
	assert.Equal(t, "\x1b[31mhi\x1b[0m", colorize(colorRed, "hi"))

	t.Setenv("NO_COLOR", "1")
	assert.Equal(t, "hi", colorize(colorRed, "hi"), "NO_COLOR must strip ANSI codes")
}
