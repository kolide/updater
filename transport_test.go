package updater

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCert struct{}

func (mc *mockCert) readPem() ([]byte, error) {
	return test.Asset("test/data/root-ca.crt")
}

func (mc *mockCert) tlsConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            pool,
	}
}

func TestCertPool(t *testing.T) {
	pool, err := certPool(&mockCert{})
	assert.Nil(t, err)
	assert.NotNil(t, pool)
}

func TestGetTransport(t *testing.T) {
	trans, err := getTransport(&mockCert{})
	assert.Nil(t, err)
	assert.NotNil(t, trans)
}

func TestPing(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()
	transport, err := getTransport(&mockCert{})
	require.Nil(t, err)
	err = pingNotary(transport, svr.URL)
	assert.Nil(t, err)
}

func TestPingWrongURL(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()
	transport, err := getTransport(&mockCert{})
	require.Nil(t, err)
	err = pingNotary(transport, "https://wrong.com:9765")

	assert.Regexp(t, regexp.MustCompile(`^could not reach notary server`), err)
}

func TestPingUnauthorized(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer svr.Close()
	transport, err := getTransport(&mockCert{})
	require.Nil(t, err)
	err = pingNotary(transport, svr.URL)
	// ping succeeds even though we get unauthorized response
	assert.Nil(t, err)
}

func TestPingRedirectFails(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// redirect
		w.WriteHeader(http.StatusFound)
	}))
	defer svr.Close()
	transport, err := getTransport(&mockCert{})
	require.Nil(t, err)
	err = pingNotary(transport, svr.URL)

	assert.NotNil(t, err)
}
