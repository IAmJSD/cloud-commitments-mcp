package tools

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maskTestKey = "test-key-SYNTHETIC-0000"

// splitKey splices sep after every character of the key.
func splitKey(sep string) string {
	return strings.Join(strings.Split(maskTestKey, ""), sep)
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

func archeraMaskCases() map[string]string {
	return map[string]string{
		"plain":            "bad key " + maskTestKey,
		"zero-width split": "bad key " + splitKey("​"),
		"bidi split":       "bad key " + splitKey("‮"),
		"control split":    "bad key " + splitKey("\x01"),
		"newline split":    "bad key " + splitKey("\n"),
		"twice":            "bad key " + maskTestKey + " and " + splitKey("​"),
		"straddles cap":    strings.Repeat("a", 250) + maskTestKey,
		"straddles split":  strings.Repeat("a", 250) + splitKey("​"),
	}
}

func TestArcheraErrorMasksKeyAfterSanitizing(t *testing.T) {
	for name, msg := range archeraMaskCases() {
		t.Run(name, func(t *testing.T) {
			got := archeraError(errors.New(msg), maskTestKey).Error()
			assert.NotContains(t, got, maskTestKey)
			assert.LessOrEqual(t, len(got), 256)
		})
	}
}

func TestArcheraErrorTrimsKeyBeforeMasking(t *testing.T) {
	got := archeraError(errors.New("bad key "+splitKey("\u200b")), " "+maskTestKey+"\n").Error()
	assert.Equal(t, "bad key [redacted]", got)
}

func TestArcheraErrorMasksKeyOnRealPaths(t *testing.T) {
	for name, echo := range archeraMaskCases() {
		t.Run("decode "+name, func(t *testing.T) {
			setArcheraEnv(t)
			t.Setenv(EnvArcheraAPIKey, maskTestKey)
			var w map[string]any
			require.NoError(t, json.Unmarshal(readWire(t), &w))
			entryOf(w, "current")["contract_term"] = echo
			body, err := json.Marshal(w)
			require.NoError(t, err)
			res, protocol, err := callArchera(t, okTransport(body), nil)
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.NotContains(t, resultText(res), maskTestKey)
			assert.NotContains(t, protocol, maskTestKey)
		})
		t.Run("transport "+name, func(t *testing.T) {
			setArcheraEnv(t)
			t.Setenv(EnvArcheraAPIKey, maskTestKey)
			res, protocol, err := callArchera(t, failingTransport{errors.New(echo)}, nil)
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.NotContains(t, resultText(res), maskTestKey)
			assert.NotContains(t, protocol, maskTestKey)
		})
	}
}

func TestArcheraErrorLeavesNoKeyPrefixAtCap(t *testing.T) {
	for _, echo := range []string{maskTestKey, splitKey("​")} {
		got := archeraError(errors.New(strings.Repeat("a", 244)+echo), maskTestKey).Error()
		assert.False(t, strings.HasSuffix(got, maskTestKey[:8]) || strings.Contains(got, maskTestKey[:8]), got)
	}
}
