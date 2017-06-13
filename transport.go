package updater

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

func getTransport(rcfg readerConfigurer) (*http.Transport, error) {
	pool, err := certPool(rcfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating notary server connection")
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     rcfg.tlsConfig(pool),
	}
	return transport, nil
}

func getAuthorizedRoundTripper(notaryServerURL string, transport *http.Transport, repoGUN string) (http.RoundTripper, error) {
	return nil, nil
}

func certPool(rdr certReader) (*x509.CertPool, error) {
	pem, err := rdr.readPem()
	if err != nil {
		return nil, errors.Wrap(err, "reading root certificate authority file")
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		return nil, errors.New("failed to append root cert")
	}
	return certPool, nil
}

func pingNotary(transport *http.Transport, notaryServerURL string) error {
	pingClient := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	endpoint, err := url.Parse(notaryServerURL)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("invalid notary server url %q", notaryServerURL))
	}
	subPath, err := url.Parse(fmt.Sprintf("%s/v2/", endpoint.Path))
	if err != nil {
		return errors.Wrap(err, "notary server path processing")
	}
	endpoint = endpoint.ResolveReference(subPath)
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.Wrap(err, "notary server ping request")
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "could not reach notary server")
	}
	defer resp.Body.Close()
	if (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) &&
		resp.StatusCode != http.StatusUnauthorized {
		// If we didn't get a 2XX range or 401 status code, we're not talking to a notary server.
		// The http client should be configured to handle redirects so at this point, 3XX is
		// not a valid status code.
		return errors.Wrap(err, "notary server is not available")
	}
	return nil
}
