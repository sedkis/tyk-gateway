package gateway

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestInboundLoopMarkersCannotReachInternalAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	var internalHits int32
	internalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&internalHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internalUpstream.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "public"
			spec.Name = "public"
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/public/"
			spec.Proxy.PreserveHostHeader = true
		},
		func(spec *APISpec) {
			spec.APIID = "billing-internal"
			spec.Name = "billing-internal"
			spec.UseKeylessAccess = true
			spec.Internal = true
			spec.Proxy.ListenPath = "/billing/"
			spec.Proxy.TargetURL = internalUpstream.URL
		},
	)

	gwURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	t.Run("absolute-form tyk:// request target", func(t *testing.T) {
		conn, err := net.Dial("tcp", gwURL.Host)
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write([]byte("GET tyk://billing-internal/public/accounts?method=DELETE HTTP/1.1\r\nHost: " + gwURL.Host + "\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, int32(0), atomic.LoadInt32(&internalHits))
	})

	t.Run("x-tyk-internal header with forged Host", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/public/accounts", nil)
		require.NoError(t, err)
		req.Host = "billing-internal"
		req.Header.Set(apidef.TykInternalApiHeader, "true")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, int32(0), atomic.LoadInt32(&internalHits))
	})
}

func TestLoopCannotCrossOrg(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "caller"
			spec.OrgID = "org-a"
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/caller/"
			spec.Proxy.TargetURL = "tyk://victim/"
		},
		func(spec *APISpec) {
			spec.APIID = "victim"
			spec.Name = "victim"
			spec.OrgID = "org-b"
			spec.UseKeylessAccess = true
			spec.Internal = true
			spec.Proxy.ListenPath = "/victim/"
		},
		func(spec *APISpec) {
			spec.APIID = "same-org-caller"
			spec.OrgID = "org-b"
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/same-org/"
			spec.Proxy.TargetURL = "tyk://victim/"
		},
	)

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/caller/", Code: http.StatusInternalServerError},
		{Path: "/same-org/", Code: http.StatusOK},
	}...)
}

func TestFuzzyFindAPIInOrg(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "other-org-api"
		spec.Name = "other org api"
		spec.OrgID = "org-b"
		spec.Internal = true
	})

	assert.NotNil(t, ts.Gw.fuzzyFindAPI("other-org-api"))
	assert.NotNil(t, ts.Gw.fuzzyFindAPIInOrg("other-org-api", "org-b"))
	assert.Nil(t, ts.Gw.fuzzyFindAPIInOrg("other-org-api", "org-a"))
	assert.NotNil(t, ts.Gw.fuzzyFindAPIInOrg("other-org-api", ""), "callers without an org are not scoped")
}
