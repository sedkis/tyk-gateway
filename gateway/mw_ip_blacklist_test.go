package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/request"
)

var testBlackListIPData = []struct {
	remote, forwarded, xRealIP string
	trusted                    bool
	wantCode                   int
}{
	{"127.0.0.1:80", "", "", false, http.StatusForbidden},        // remote exact match
	{"127.0.0.2:80", "", "", false, http.StatusForbidden},        // remote CIDR match
	{"10.0.0.1:80", "", "", false, http.StatusOK},                // no match
	{"10.0.0.1:80", "127.0.0.1", "", false, http.StatusOK},       // untrusted forwarded exact match
	{"10.0.0.1:80", "127.0.0.1", "", true, http.StatusForbidden}, // trusted forwarded exact match
	{"10.0.0.1:80", "127.0.0.2", "", false, http.StatusOK},       // untrusted forwarded CIDR match
	{"10.0.0.1:80", "127.0.0.2", "", true, http.StatusForbidden}, // trusted forwarded CIDR match
	{"10.0.0.1:80", "", "127.0.0.1", false, http.StatusOK},       // untrusted X-Real-IP
	{"10.0.0.1:80", "", "127.0.0.1", true, http.StatusForbidden}, // trusted X-Real-IP
	{"10.0.0.1:80", "", "bob", false, http.StatusOK},             // no match
}

func testPrepareIPBlacklistMiddleware() *APISpec {
	return BuildAPI(func(spec *APISpec) {
		spec.EnableIpBlacklisting = true
		spec.BlacklistedIPs = []string{"127.0.0.1", "127.0.0.1/24", "bob"}
	})[0]
}

func TestIPBlackListMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name       string
		spec       *APISpec
		wantResult bool
	}{
		{
			name: "IpBlacklisting enabled and BlacklistedIPs not empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					EnableIpBlacklisting: true,
					BlacklistedIPs:       []string{"192.168.1.1"},
				},
			},
			wantResult: true,
		},
		{
			name: "IpBlacklisting disabled and IPAccessControl disabled and BlacklistedIPs not empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					EnableIpBlacklisting:    false,
					IPAccessControlDisabled: true,
					BlacklistedIPs:          []string{"192.168.1.1"},
				},
			},
			wantResult: false,
		},
		{
			name: "IpBlacklisting enabled and BlacklistedIPs empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					EnableIpBlacklisting: true,
					BlacklistedIPs:       []string{},
				},
			},
			wantResult: false,
		},
		{
			name: "IpBlacklisting disabled and BlacklistedIPs empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					EnableIpBlacklisting: false,
					BlacklistedIPs:       []string{},
				},
			},
			wantResult: false,
		},
		{
			name: "IPAccessControlDisabled true and BlacklistedIPs not empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					IPAccessControlDisabled: true,
					BlacklistedIPs:          []string{"192.168.1.1"},
				},
			},
			wantResult: false,
		},
		{
			name: "IPAccessControlDisabled false and BlacklistedIPs not empty",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					IPAccessControlDisabled: false,
					BlacklistedIPs:          []string{"192.168.1.1"},
				},
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &IPBlackListMiddleware{BaseMiddleware: &BaseMiddleware{Spec: tt.spec}}
			gotResult := middleware.EnabledForSpec()
			assert.Equal(t, tt.wantResult, gotResult)
		})
	}
}
func TestIPBlacklistMiddleware(t *testing.T) {
	oldGlobal := request.Global
	defer func() { request.Global = oldGlobal }()

	spec := testPrepareIPBlacklistMiddleware()

	for ti, tc := range testBlackListIPData {
		setIPMiddlewareConfig(tc.trusted)
		rec := httptest.NewRecorder()
		req := TestReq(t, "GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}

		if tc.xRealIP != "" {
			req.Header.Set(header.XRealIP, tc.xRealIP)
		}

		mw := &IPBlackListMiddleware{BaseMiddleware: &BaseMiddleware{}}
		mw.Spec = spec
		_, code := mw.ProcessRequest(rec, req, nil)

		if code != tc.wantCode {
			t.Errorf("[%d] Response code %d should be %d\n%q %q", ti,
				code, tc.wantCode, tc.remote, tc.forwarded)
		}
	}
}

func BenchmarkIPBlacklistMiddleware(b *testing.B) {
	b.ReportAllocs()

	spec := testPrepareIPBlacklistMiddleware()

	mw := &IPBlackListMiddleware{BaseMiddleware: &BaseMiddleware{}}
	mw.Spec = spec

	rec := httptest.NewRecorder()
	for i := 0; i < b.N; i++ {
		for ti, tc := range testBlackListIPData {
			setIPMiddlewareConfig(tc.trusted)
			req := TestReq(b, "GET", "/", nil)
			req.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}

			if tc.xRealIP != "" {
				req.Header.Set(header.XRealIP, tc.xRealIP)
			}

			_, code := mw.ProcessRequest(rec, req, nil)
			if code != tc.wantCode {
				b.Errorf("[%d] Response code %d should be %d\n%q %q", ti,
					code, tc.wantCode, tc.remote, tc.forwarded)
			}
		}
	}
}
