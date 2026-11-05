package streams

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// fakeGateway mimics gateway.ReplaceTykVariables for $tyk_context.headers_* and
// $secret_env.*, including the "http" prefix escaping exemption.
type fakeGateway struct {
	headers map[string]string
	env     map[string]string
}

var fakeVarMatch = regexp.MustCompile(`\$(tyk_context\.headers_|secret_env\.)([A-Za-z0-9_\-\.]+)`)

func (g *fakeGateway) GetConfig() config.Config { return config.Config{} }

func (g *fakeGateway) ReplaceTykVariables(_ *http.Request, in string, escape bool) string {
	return fakeVarMatch.ReplaceAllStringFunc(in, func(v string) string {
		m := fakeVarMatch.FindStringSubmatch(v)
		if m[1] == "secret_env." {
			return g.env[m[2]]
		}
		val := g.headers[m[2]]
		if escape && !strings.HasPrefix(val, "http") {
			val = url.QueryEscape(val)
		}
		return val
	})
}

type fakeBase struct{}

func (fakeBase) Logger() *logrus.Entry { return logrus.NewEntry(logrus.New()) }

func newTestMiddleware(gw Gateway) *Middleware {
	return NewMiddleware(gw, fakeBase{}, &APISpec{}, nil)
}

func kafkaStream(consumerGroup string) map[string]any {
	return map[string]any{
		"input": map[string]any{
			"kafka": map[string]any{
				"addresses":      []any{"localhost:9092"},
				"topics":         []any{"test"},
				"consumer_group": consumerGroup,
			},
		},
		"output": map[string]any{
			"http_server": map[string]any{"ws_path": "/subscribe"},
		},
	}
}

func TestProcessStreamsConfig_RequestValueCannotInjectConfig(t *testing.T) {
	payload := `http", "pipeline": {"processors": [{"bloblang": "root = \"x\""}]}, "y": "`
	gw := &fakeGateway{headers: map[string]string{"X_Client": payload}}
	mw := newTestMiddleware(gw)

	original := kafkaStream("$tyk_context.headers_X_Client")
	streams := map[string]any{"s1": original}
	cfg := &StreamsConfig{Streams: map[string]any{}}

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	mw.processStreamsConfig(r, streams, cfg)

	resolved, ok := cfg.Streams["s1"].(map[string]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"input", "output"}, keys(resolved))
	assert.NotContains(t, resolved, "pipeline")
	assert.NotContains(t, resolved, "y")

	kafka := resolved["input"].(map[string]any)["kafka"].(map[string]any)
	assert.ElementsMatch(t, []string{"addresses", "topics", "consumer_group"}, keys(kafka))
	assert.Equal(t, url.QueryEscape(payload), kafka["consumer_group"])

	// The spec's original config must not be mutated.
	origKafka := original["input"].(map[string]any)["kafka"].(map[string]any)
	assert.Equal(t, "$tyk_context.headers_X_Client", origKafka["consumer_group"])
}

func TestProcessStreamsConfig_ReplacesVariablesInStringLeaves(t *testing.T) {
	gw := &fakeGateway{
		headers: map[string]string{"X_Client": "client a", "X_Url": "http://example.com/a b"},
		env:     map[string]string{"TOPIC": "orders"},
	}
	mw := newTestMiddleware(gw)

	stream := map[string]any{
		"input": map[string]any{
			"kafka": map[string]any{
				"topics":         []any{"$secret_env.TOPIC", "static"},
				"consumer_group": "group:$tyk_context.headers_X_Client:$secret_env.TOPIC",
				"url":            "$tyk_context.headers_X_Url",
				"max_in_flight":  float64(10),
				"enabled":        true,
			},
		},
	}
	cfg := &StreamsConfig{Streams: map[string]any{}}

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	mw.processStreamsConfig(r, map[string]any{"s1": stream}, cfg)

	kafka := cfg.Streams["s1"].(map[string]any)["input"].(map[string]any)["kafka"].(map[string]any)
	assert.Equal(t, []any{"orders", "static"}, kafka["topics"])
	assert.Equal(t, "group:client+a:orders", kafka["consumer_group"])
	assert.Equal(t, url.QueryEscape("http://example.com/a b"), kafka["url"])
	assert.Equal(t, float64(10), kafka["max_in_flight"])
	assert.Equal(t, true, kafka["enabled"])
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
