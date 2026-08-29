package request

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

var ipHeaderTests = []struct {
	remoteAddr string
	key        string
	value      string
	expected   string
	comment    string
}{
	{remoteAddr: "10.0.1.4:8080", key: "X-Real-IP", value: "10.0.0.1", expected: "10.0.1.4", comment: "untrusted X-Real-IP"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "10.0.0.2", expected: "10.0.1.4", comment: "untrusted X-Forwarded-For (single)"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "10.0.0.3, 10.0.0.2, 10.0.0.1", expected: "10.0.1.4", comment: "untrusted X-Forwarded-For (multiple)"},
	{remoteAddr: "10.0.1.4:8080", expected: "10.0.1.4", comment: "RemoteAddr"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "bob", expected: "10.0.1.4", comment: "invalid X-Forwarded-For"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Real-IP", value: "bob", expected: "10.0.1.4", comment: "invalid X-Real-IP"},
}

func TestRealIP(t *testing.T) {
	// Forwarding headers are ignored by default.
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	for _, test := range ipHeaderTests {
		t.Log(test.comment)

		r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.key != "" {
			r.Header.Set(test.key, test.value)
		}
		r.RemoteAddr = test.remoteAddr

		ip := RealIP(r)

		if ip != test.expected {
			t.Errorf("\texpected %s got %s", test.expected, ip)
		}
	}

	t.Log("Context")
	r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(r.Context(), "remote_addr", "10.0.0.5")
	r = r.WithContext(ctx)

	ip := RealIP(r)
	if ip != "10.0.0.5" {
		t.Errorf("\texpected %s got %s", "10.0.0.5", ip)
	}

	t.Run("TrustAllProxies preserves XFFDepth", func(t *testing.T) {
		mockConfig.HttpServerOptions.TrustedProxies = nil
		mockConfig.HttpServerOptions.TrustAllProxies = true
		r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.RemoteAddr = "10.0.1.4:8080"
		r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")

		for _, test := range []struct {
			depth    int
			expected string
		}{
			{depth: 1, expected: "10.0.0.1"},
			{depth: 2, expected: "10.0.0.2"},
		} {
			mockConfig.HttpServerOptions.XFFDepth = test.depth
			if ip := RealIP(r); ip != test.expected {
				t.Errorf("XFFDepth=%d: expected %s got %s", test.depth, test.expected, ip)
			}
		}
	})

	t.Run("configured trusted proxies", func(t *testing.T) {
		mockConfig.HttpServerOptions.TrustedProxies = []string{"10.0.1.0/24", "192.168.1.1"}

		tests := []struct {
			name       string
			remoteAddr string
			header     string
			value      string
			expected   string
		}{
			{
				name:       "trusted CIDR with X-Real-IP",
				remoteAddr: "10.0.1.4:8080",
				header:     "X-Real-IP",
				value:      "10.0.0.1",
				expected:   "10.0.0.1",
			},
			{
				name:       "trusted exact IP with X-Forwarded-For",
				remoteAddr: "192.168.1.1:8080",
				header:     "X-Forwarded-For",
				value:      "10.0.0.2",
				expected:   "10.0.0.2",
			},
			{
				name:       "untrusted peer",
				remoteAddr: "203.0.113.9:1234",
				header:     "X-Forwarded-For",
				value:      "10.0.0.3",
				expected:   "203.0.113.9",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
				if err != nil {
					t.Fatal(err)
				}
				r.RemoteAddr = test.remoteAddr
				r.Header.Set(test.header, test.value)

				if ip := RealIP(r); ip != test.expected {
					t.Errorf("expected %s got %s", test.expected, ip)
				}
			})
		}
	})

	t.Run("X-Forwarded-For takes precedence over X-Real-IP", func(t *testing.T) {
		mockConfig.HttpServerOptions.TrustedProxies = nil
		mockConfig.HttpServerOptions.TrustAllProxies = true
		mockConfig.HttpServerOptions.XFFDepth = 1

		r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.RemoteAddr = "10.0.1.4:8080"
		r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")
		r.Header.Set("X-Real-IP", "10.0.0.9")

		if ip := RealIP(r); ip != "10.0.0.1" {
			t.Errorf("expected %s got %s", "10.0.0.1", ip)
		}

		r.Header.Set("X-Forwarded-For", "invalid-ip")
		if ip := RealIP(r); ip != "10.0.0.9" {
			t.Errorf("expected %s got %s", "10.0.0.9", ip)
		}

		r.Header.Del("X-Forwarded-For")
		if ip := RealIP(r); ip != "10.0.0.9" {
			t.Errorf("expected %s got %s", "10.0.0.9", ip)
		}
	})
}

func BenchmarkRealIP_RemoteAddr(b *testing.B) {
	b.ReportAllocs()

	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	mockConfig.HttpServerOptions.TrustAllProxies = true
	Global = func() config.Config {
		return mockConfig
	}

	r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	if err != nil {
		b.Fatal(err)
	}
	r.RemoteAddr = "10.0.1.4:8081"

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.1.4" {
			b.Errorf("\texpected %s got %s", "10.0.1.4", ip)
		}
	}
}

func BenchmarkRealIP_ForwardedFor(b *testing.B) {
	b.ReportAllocs()

	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	mockConfig.HttpServerOptions.TrustAllProxies = true
	Global = func() config.Config {
		return mockConfig
	}

	r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	if err != nil {
		b.Fatal(err)
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.3" {
			b.Errorf("\texpected %s got %s", "10.0.1.3", ip)
		}
	}
}

func BenchmarkRealIP_RealIP(b *testing.B) {
	b.ReportAllocs()

	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	mockConfig.HttpServerOptions.TrustAllProxies = true
	Global = func() config.Config {
		return mockConfig
	}

	r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	if err != nil {
		b.Fatal(err)
	}
	r.Header.Set("X-Real-IP", "10.0.0.1")

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.1" {
			b.Errorf("\texpected %s got %s", "10.0.0.1", ip)
		}
	}
}

func BenchmarkRealIP_Context(b *testing.B) {
	b.ReportAllocs()

	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	mockConfig.HttpServerOptions.TrustAllProxies = true
	Global = func() config.Config {
		return mockConfig
	}

	r, err := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	if err != nil {
		b.Fatal(err)
	}
	r.Header.Set("X-Real-IP", "10.0.0.1")
	ctx := context.WithValue(r.Context(), "remote_addr", "10.0.0.5")
	r = r.WithContext(ctx)

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.5" {
			b.Errorf("\texpected %s got %s", "10.0.0.5", ip)
		}
	}
}

func TestXFFDepth(t *testing.T) {
	// Define test cases for XFFDepth
	testCases := []struct {
		name     string
		xffValue string
		depth    int
		expected string
	}{
		{
			name:     "Depth 1 (last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    1,
			expected: "13.0.0.1",
		},
		{
			name:     "Depth 2 (second to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    2,
			expected: "12.0.0.1",
		},
		{
			name:     "Depth 3 (third to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    3,
			expected: "11.0.0.1",
		},
		{
			name:     "Depth 4 (fourth to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    4,
			expected: "10.0.0.1",
		},
		{
			name:     "Depth 5 (exceeds chain length)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    5,
			expected: "",
		},
		{
			name:     "Depth 0 (first IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    0,
			expected: "10.0.0.1",
		},
		{
			name:     "Depth -5 (Negative Depth uses same as NO depth)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    -5,
			expected: "",
		},
		{
			name:     "Header with spaces",
			xffValue: "10.0.0.1, 11.0.0.1, 12.0.0.1, 13.0.0.1",
			depth:    2,
			expected: "12.0.0.1",
		},
		{
			name:     "Header with mixed format",
			xffValue: "10.0.0.1,11.0.0.1, 12.0.0.1,  13.0.0.1",
			depth:    3,
			expected: "11.0.0.1",
		},
		{
			name:     "Empty header",
			xffValue: "",
			depth:    0,
			expected: "192.168.1.1", // Should fall back to RemoteAddr
		},
		{
			name:     "Invalid IP at selected depth",
			xffValue: "10.0.0.1,invalid-ip,12.0.0.1,13.0.0.1",
			depth:    3,
			expected: "192.168.1.1", // Should fall back to RemoteAddr
		},
	}

	// Initialize mock config for tests
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.TrustAllProxies = true

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set the XFFDepth for this test case
			mockConfig.HttpServerOptions.XFFDepth = tc.depth
			Global = func() config.Config {
				return mockConfig
			}

			// Create request with X-Forwarded-For header
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("X-Forwarded-For", tc.xffValue)
			r.RemoteAddr = "192.168.1.1:8080" // Fallback IP if XFF processing fails

			// Get client IP
			ip := RealIP(r)

			// Check result
			if ip != tc.expected {
				t.Errorf("Expected IP %q, got %q", tc.expected, ip)
			}
		})
	}
}
