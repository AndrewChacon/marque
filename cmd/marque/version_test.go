package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionString_IncludesAllFields(t *testing.T) {
	s := versionString()
	assert.Contains(t, s, version)
	assert.Contains(t, s, commit)
	assert.Contains(t, s, date)
}

func TestVersionCmd_PrintsVersionString(t *testing.T) {
	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Equal(t, versionString()+"\n", out.String())
}

func TestRootCmd_VersionFlagDoesNotDoubleUpTheBinaryName(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})

	require.NoError(t, root.Execute())
	assert.Equal(t, "marque version "+versionDetails()+"\n", out.String())
}
