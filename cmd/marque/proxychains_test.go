package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintProxychainsConfig(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printProxychainsConfig(&out, "127.0.0.1:1080"))

	output := out.String()
	assert.Contains(t, output, "[ProxyList]")
	assert.Contains(t, output, "socks5 127.0.0.1 1080")
}

func TestPrintProxychainsConfig_CustomAddr(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printProxychainsConfig(&out, "0.0.0.0:9999"))
	assert.Contains(t, out.String(), "socks5 0.0.0.0 9999")
}

func TestPrintProxychainsConfig_InvalidAddrIsActionable(t *testing.T) {
	var out bytes.Buffer
	err := printProxychainsConfig(&out, "not-an-address")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--listen")
}

func TestProxychainsConfigCmd_DefaultsMatchProxyDefault(t *testing.T) {
	cmd := newProxychainsConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "socks5 127.0.0.1 1080")
}
