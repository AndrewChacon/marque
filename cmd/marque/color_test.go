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

func TestColorize_NoColorSetToEmptyStringStillDisables(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	assert.Equal(t, "hi", colorize(colorRed, "hi"), "NO_COLOR merely being present must disable color, regardless of its value")
}
