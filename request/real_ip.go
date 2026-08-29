package request

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

var Global func() config.Config

var (
	trustedProxyMu   sync.RWMutex
	trustedProxyKey  string
	trustedProxyIPs  []net.IP
	trustedProxyNets []*net.IPNet
)

// RealIP takes a request object, and returns the real Client IP address.
//
// The client supplied forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are
// only consulted when the request reached the Gateway through a proxy declared
// in `http_server_options.trusted_proxies` (or when
// `http_server_options.trust_all_proxies` is enabled). For any other request
// the transport level address is used, so that a client can not spoof its own
// IP address to pass an IP allow list or evade an IP block list.
func RealIP(r *http.Request) string {

	if contextIp := r.Context().Value("remote_addr"); contextIp != nil {
		return contextIp.(string)
	}

	// From net/http.Request.RemoteAddr:
	//   The HTTP server in this package sets RemoteAddr to an
	//   "IP:port" address before invoking a handler.
	// So we can ignore the case of the port missing.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)

	if !trustForwardedHeaders(host) {
		return host
	}

	// X-Forwarded-For is evaluated before X-Real-IP so that the configured
	// XFFDepth is applied consistently and can not be sidestepped by sending
	// an X-Real-IP header.
	if fw := r.Header.Get(header.XForwardFor); fw != "" {
		xffs := strings.Split(fw, ",")

		// Get depth from config, default to 0 (first IP in chain)
		var depth int
		if Global != nil {
			depth = Global().HttpServerOptions.XFFDepth
		}

		// The following check for invalid depth configs.
		// It's more secure to return empty if depth is invalid.
		// Defaulting to an IP from the request would be
		// burying a configuration failure.
		if depth < 0 || depth > len(xffs) {
			return ""
		}

		// Choose the appropriate IP based on depth
		// depth=0 means first IP (leftmost), depth=1 means last IP, depth=2 means second to last, etc.
		// Negative depth is invalid and treated same as 0/unset.
		var ip string
		if depth == 0 {
			ip = strings.TrimSpace(xffs[0])
		} else {
			ip = strings.TrimSpace(xffs[len(xffs)-depth])
		}

		// Validate that the IP is properly formatted before returning it
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return parsedIP.String()
		}
		// If IP is invalid, fall through to use RemoteAddr
	}

	if realIPVal := r.Header.Get(header.XRealIP); realIPVal != "" {
		if realIP := net.ParseIP(realIPVal); realIP != nil {
			return realIP.String()
		}
	}

	return host
}

// trustForwardedHeaders reports whether the client supplied IP forwarding
// headers of a request coming from remoteAddr may be used to derive the client
// IP address. Forwarding headers are not trusted unless the operator declared
// the peer as a trusted proxy.
func trustForwardedHeaders(remoteAddr string) bool {
	if Global == nil {
		return false
	}

	opts := Global().HttpServerOptions

	if opts.TrustAllProxies {
		return true
	}

	if len(opts.TrustedProxies) == 0 {
		return false
	}

	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return false
	}

	ips, nets := trustedProxies(opts.TrustedProxies)

	for _, trustedNet := range nets {
		if trustedNet.Contains(ip) {
			return true
		}
	}

	for _, trustedIP := range ips {
		if trustedIP.Equal(ip) {
			return true
		}
	}

	return false
}

// trustedProxies parses the configured trusted proxy entries into IPs and
// networks, caching the result for the current configuration value. Entries
// that are neither a valid IP address nor a valid CIDR range are ignored.
func trustedProxies(list []string) ([]net.IP, []*net.IPNet) {
	key := strings.Join(list, ",")

	trustedProxyMu.RLock()
	if key == trustedProxyKey {
		ips, nets := trustedProxyIPs, trustedProxyNets
		trustedProxyMu.RUnlock()
		return ips, nets
	}
	trustedProxyMu.RUnlock()

	var (
		ips  []net.IP
		nets []*net.IPNet
	)

	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, trustedNet, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, trustedNet)
			continue
		}

		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip)
		}
	}

	trustedProxyMu.Lock()
	trustedProxyKey, trustedProxyIPs, trustedProxyNets = key, ips, nets
	trustedProxyMu.Unlock()

	return ips, nets
}
