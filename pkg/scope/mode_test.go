package scope

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMode_String(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeEnforce, "enforce"},
		{ModeWarn, "warn"},
		{ModeDryRun, "dry-run"},
		{Mode(99), "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.mode.String())
		})
	}
}

func TestMode_MarshalJSON(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeEnforce, `"enforce"`},
		{ModeWarn, `"warn"`},
		{ModeDryRun, `"dry-run"`},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			out, err := json.Marshal(tc.mode)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(out))
		})
	}
}

func TestMode_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		json string
		want Mode
	}{
		{`"enforce"`, ModeEnforce},
		{`"warn"`, ModeWarn},
		{`"dry-run"`, ModeDryRun},
		{`"dryrun"`, ModeDryRun},
		{`""`, ModeEnforce},
	}
	for _, tc := range cases {
		t.Run(tc.json, func(t *testing.T) {
			var m Mode
			require.NoError(t, json.Unmarshal([]byte(tc.json), &m))
			assert.Equal(t, tc.want, m)
		})
	}
}

func TestMode_UnmarshalJSON_Invalid(t *testing.T) {
	var m Mode
	err := json.Unmarshal([]byte(`"yolo"`), &m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

func TestMode_UnmarshalJSON_NotAString(t *testing.T) {
	var m Mode
	err := json.Unmarshal([]byte(`42`), &m)
	require.Error(t, err)
}

func TestMode_JSONRoundTrip(t *testing.T) {
	for _, mode := range []Mode{ModeEnforce, ModeWarn, ModeDryRun} {
		t.Run(mode.String(), func(t *testing.T) {
			out, err := json.Marshal(mode)
			require.NoError(t, err)

			var back Mode
			require.NoError(t, json.Unmarshal(out, &back))
			assert.Equal(t, mode, back)
		})
	}
}
