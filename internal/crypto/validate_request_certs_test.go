package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parsePEMCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// allowedCert mimics how the certificate manager stores certificates: Leaf is set
// and Extensions[0] caches the certificate SHA256.
func allowedCert(cert *x509.Certificate) *tls.Certificate {
	leaf := *cert
	leaf.Extensions = append([]pkix.Extension{{Value: []byte(HexSHA256(cert.Raw))}}, cert.Extensions...)
	return &tls.Certificate{Certificate: [][]byte{cert.Raw}, Leaf: &leaf}
}

func requestWithPeers(peers ...*x509.Certificate) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://localhost/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: peers}
	return r
}

func TestValidateRequestCerts(t *testing.T) {
	rootCertPEM, rootKeyPEM, err := GenerateRootCertAndKey(t)
	require.NoError(t, err)
	caCert := parsePEMCert(t, rootCertPEM)

	clientCertPEM, _, err := GenerateClientCertAndKeyPEM(t, rootCertPEM, rootKeyPEM)
	require.NoError(t, err)
	clientCert := parsePEMCert(t, clientCertPEM.Bytes())

	serverCertPEM, _, err := GenerateServerCertAndKeyPEM(t, rootCertPEM, rootKeyPEM)
	require.NoError(t, err)
	serverOnlyCert := parsePEMCert(t, serverCertPEM.Bytes())

	attackerPEM, _, _, _ := GenCertificate(&x509.Certificate{Subject: pkix.Name{CommonName: "attacker"}}, false)
	attackerCert := parsePEMCert(t, attackerPEM)

	t.Run("no TLS", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
		assert.Error(t, ValidateRequestCerts(r, []*tls.Certificate{allowedCert(caCert)}))
	})

	t.Run("no peer certificates", func(t *testing.T) {
		assert.ErrorIs(t, ValidateRequestCerts(requestWithPeers(), []*tls.Certificate{allowedCert(caCert)}), ErrTlsRequired)
	})

	t.Run("CA signed leaf with CA in chain is allowed by CA", func(t *testing.T) {
		assert.NoError(t, ValidateRequestCerts(requestWithPeers(clientCert, caCert), []*tls.Certificate{allowedCert(caCert)}))
	})

	t.Run("CA signed leaf without chain is allowed by CA", func(t *testing.T) {
		assert.NoError(t, ValidateRequestCerts(requestWithPeers(clientCert), []*tls.Certificate{allowedCert(caCert)}))
	})

	t.Run("pinned leaf is allowed", func(t *testing.T) {
		assert.NoError(t, ValidateRequestCerts(requestWithPeers(clientCert), []*tls.Certificate{nil, allowedCert(clientCert)}))
	})

	t.Run("self signed leaf with appended allowed CA is rejected", func(t *testing.T) {
		assert.Error(t, ValidateRequestCerts(requestWithPeers(attackerCert, caCert), []*tls.Certificate{allowedCert(caCert)}))
	})

	t.Run("self signed leaf with appended pinned cert is rejected", func(t *testing.T) {
		assert.Error(t, ValidateRequestCerts(requestWithPeers(attackerCert, clientCert), []*tls.Certificate{allowedCert(clientCert)}))
	})

	t.Run("CA signed leaf without client auth usage is rejected by CA", func(t *testing.T) {
		assert.Error(t, ValidateRequestCerts(requestWithPeers(serverOnlyCert, caCert), []*tls.Certificate{allowedCert(caCert)}))
	})

	t.Run("leaf not signed by allowed CA is rejected", func(t *testing.T) {
		otherRootPEM, _, err := GenerateRootCertAndKey(t)
		require.NoError(t, err)
		otherCA := parsePEMCert(t, otherRootPEM)
		assert.Error(t, ValidateRequestCerts(requestWithPeers(clientCert, caCert), []*tls.Certificate{allowedCert(otherCA)}))
	})
}

func TestValidateRequestCerts_AllowedChain(t *testing.T) {
	rootCertPEM, rootKeyPEM, err := GenerateRootCertAndKey(t)
	require.NoError(t, err)
	caCert := parsePEMCert(t, rootCertPEM)

	storedPEM, _, err := GenerateClientCertAndKeyPEM(t, rootCertPEM, rootKeyPEM)
	require.NoError(t, err)
	storedLeaf := parsePEMCert(t, storedPEM.Bytes())

	otherPEM, _, err := GenerateClientCertAndKeyPEM(t, rootCertPEM, rootKeyPEM)
	require.NoError(t, err)
	otherClient := parsePEMCert(t, otherPEM.Bytes())

	attackerPEM, _, _, _ := GenCertificate(&x509.Certificate{Subject: pkix.Name{CommonName: "attacker"}}, false)
	attackerCert := parsePEMCert(t, attackerPEM)

	// A stored chain [leaf, CA]: like the certificate manager, Leaf is the first cert
	// and the cached fingerprint is the SHA256 of the last cert.
	leaf := *storedLeaf
	leaf.Extensions = append([]pkix.Extension{{Value: []byte(HexSHA256(caCert.Raw))}}, storedLeaf.Extensions...)
	chain := &tls.Certificate{Certificate: [][]byte{storedLeaf.Raw, caCert.Raw}, Leaf: &leaf}

	t.Run("leaf signed by CA from allowed chain is allowed", func(t *testing.T) {
		assert.NoError(t, ValidateRequestCerts(requestWithPeers(otherClient, caCert), []*tls.Certificate{chain}))
	})

	t.Run("self signed leaf with appended CA from allowed chain is rejected", func(t *testing.T) {
		assert.Error(t, ValidateRequestCerts(requestWithPeers(attackerCert, caCert), []*tls.Certificate{chain}))
	})
}
