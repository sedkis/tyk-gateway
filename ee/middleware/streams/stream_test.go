package streams

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestStreamStart(t *testing.T) {
	str := NewStream(nil, testLogger())
	require.NotNil(t, str)

	t.Run("success", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_path": "/subscribe",
				},
			},
		}, nil)
		require.NoError(t, err)
	})

	t.Run("fail due to bad schema", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_pat": "/subscribe",
				},
			},
		}, nil)
		require.Error(t, err)
	})
}

func TestStreamStop(t *testing.T) {
	logger := testLogger()
	validConfig := map[string]interface{}{
		"input": map[string]interface{}{
			"http_server": map[string]interface{}{
				"path": "/post",
			},
		},
		"output": map[string]interface{}{
			"http_server": map[string]interface{}{
				"ws_path": "/subscribe",
			},
		},
	}
	t.Run("successfully stop", func(t *testing.T) {
		str := NewStream(nil, logger)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		err = str.Stop()
		require.NoError(t, err)
	})

	t.Run("no error stopping cause no stream", func(t *testing.T) {
		str := NewStream(nil, logger)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		str.stream = nil
		require.NoError(t, str.Stop())
	})
}

func TestUnsafeComponentsBlocked(t *testing.T) {
	httpOutput := map[string]interface{}{
		"http_server": map[string]interface{}{"ws_path": "/subscribe"},
	}
	httpInput := map[string]interface{}{
		"http_server": map[string]interface{}{"path": "/post"},
	}

	testCases := []struct {
		name      string
		component string
		config    map[string]interface{}
	}{
		{
			name:      "top-level input",
			component: "file",
			config: map[string]interface{}{
				"input":  map[string]interface{}{"file": map[string]interface{}{"paths": []string{"test.txt"}}},
				"output": httpOutput,
			},
		},
		{
			name:      "top-level output",
			component: "socket",
			config: map[string]interface{}{
				"input":  httpInput,
				"output": map[string]interface{}{"socket": map[string]interface{}{"network": "tcp", "address": "localhost:1234"}},
			},
		},
		{
			name:      "pipeline processor list item",
			component: "subprocess",
			config: map[string]interface{}{
				"input": httpInput,
				"pipeline": map[string]interface{}{
					"processors": []interface{}{
						map[string]interface{}{"subprocess": map[string]interface{}{"name": "sh", "args": []string{"-c", "id"}}},
					},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "input processor list item",
			component: "command",
			config: map[string]interface{}{
				"input": map[string]interface{}{
					"http_server": map[string]interface{}{"path": "/post"},
					"processors": []interface{}{
						map[string]interface{}{"command": map[string]interface{}{"name": "sh", "args_mapping": `["-c", "id"]`}},
					},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "broker input list item",
			component: "file",
			config: map[string]interface{}{
				"input": map[string]interface{}{
					"broker": map[string]interface{}{
						"inputs": []interface{}{
							httpInput,
							map[string]interface{}{"file": map[string]interface{}{"paths": []string{"/etc/passwd"}}},
						},
					},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "broker output list item",
			component: "file",
			config: map[string]interface{}{
				"input": httpInput,
				"output": map[string]interface{}{
					"broker": map[string]interface{}{
						"outputs": []interface{}{
							httpOutput,
							map[string]interface{}{"file": map[string]interface{}{"path": "/tmp/out"}},
						},
					},
				},
			},
		},
		{
			name:      "processor resource",
			component: "subprocess",
			config: map[string]interface{}{
				"input": httpInput,
				"processor_resources": []interface{}{
					map[string]interface{}{"label": "run", "subprocess": map[string]interface{}{"name": "sh"}},
				},
				"pipeline": map[string]interface{}{
					"processors": []interface{}{map[string]interface{}{"resource": "run"}},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "cache resource",
			component: "file",
			config: map[string]interface{}{
				"input": httpInput,
				"cache_resources": []interface{}{
					map[string]interface{}{"label": "c", "file": map[string]interface{}{"directory": "/tmp"}},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "explicit type field",
			component: "subprocess",
			config: map[string]interface{}{
				"input": httpInput,
				"pipeline": map[string]interface{}{
					"processors": []interface{}{
						map[string]interface{}{"type": "subprocess", "subprocess": map[string]interface{}{"name": "sh"}},
					},
				},
				"output": httpOutput,
			},
		},
		{
			name:      "nested in switch processor",
			component: "subprocess",
			config: map[string]interface{}{
				"input": httpInput,
				"pipeline": map[string]interface{}{
					"processors": []interface{}{
						map[string]interface{}{"switch": []interface{}{
							map[string]interface{}{
								"check": "true",
								"processors": []interface{}{
									map[string]interface{}{"subprocess": map[string]interface{}{"name": "sh"}},
								},
							},
						}},
					},
				},
				"output": httpOutput,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			str := NewStream(nil, testLogger())
			err := str.Start(tc.config, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "component '"+tc.component+"' is disabled")
			require.Nil(t, str.stream)
		})
	}
}

func TestAllowlistedUnsafeComponents(t *testing.T) {
	config := map[string]interface{}{
		"input": map[string]interface{}{
			"http_server": map[string]interface{}{"path": "/post"},
		},
		"pipeline": map[string]interface{}{
			"processors": []interface{}{
				map[string]interface{}{"command": map[string]interface{}{"name": "true"}},
			},
		},
		"output": map[string]interface{}{
			"http_server": map[string]interface{}{"ws_path": "/subscribe"},
		},
	}

	t.Run("blocked when not allowlisted", func(t *testing.T) {
		str := NewStream([]string{"file"}, testLogger())
		require.Error(t, str.Start(config, nil))
	})

	t.Run("allowed when allowlisted", func(t *testing.T) {
		str := NewStream([]string{"command"}, testLogger())
		require.NoError(t, str.Start(config, nil))
		require.NoError(t, str.Stop())
	})
}

func testLogger() *logrus.Entry {
	return logrus.NewEntry(logrus.New())
}
