package tuf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

// optional args
type roleVersion int

// pass optional role version to root()
func version(v int) func() interface{} {
	return func() interface{} {
		return roleVersion(v)
	}
}

type expectedSizeType int64

func expectedSize(size int64) func() interface{} {
	return func() interface{} {
		return expectedSizeType(size)
	}
}

type tester interface {
	test([]byte) error
}

func testSHA256(hash string) func() interface{} {
	return func() interface{} {
		return &hashTester{
			encodedHash: hash,
			hasher: func(b []byte) []byte {
				h := sha256.Sum256(b)
				return h[:]
			},
		}
	}
}

func testSHA512(hash string) func() interface{} {
	return func() interface{} {
		return &hashTester{
			encodedHash: hash,
			hasher: func(b []byte) []byte {
				h := sha512.Sum512(b)
				return h[:]
			},
		}
	}
}

func (r *notaryRepo) root(opts ...func() interface{}) (*Root, error) {
	roleVal := roleRoot
	for _, opt := range opts {
		switch t := opt().(type) {
		case roleVersion:
			roleVal = role(fmt.Sprintf("%d.%s", t, roleRoot))
		}
	}
	var root Root
	err := r.getRole(roleVal, &root)
	if err != nil {
		return nil, err
	}
	return &root, nil
}

func (r *notaryRepo) targets(opts ...func() interface{}) (*Targets, error) {
	var targets Targets
	err := r.getRole(roleTargets, &targets, opts...)
	if err != nil {
		return nil, err
	}
	return &targets, nil
}

func (r *notaryRepo) timestamp() (*Timestamp, error) {
	var timestamp Timestamp
	err := r.getRole(roleTimestamp, &timestamp)
	if err != nil {
		return nil, err
	}
	return &timestamp, nil
}

func (r *notaryRepo) snapshot(opts ...func() interface{}) (*Snapshot, error) {
	var snapshot Snapshot
	err := r.getRole(roleSnapshot, &snapshot, opts...)
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// Returns nil if notary server is responding
func (r *notaryRepo) ping() error {
	path, err := url.Parse(healthzPath)
	if err != nil {
		return errors.Wrap(err, "ping")
	}
	pingURL := r.url.ResolveReference(path).String()
	client := r.getClient()
	resp, err := client.Get(pingURL)
	if err != nil {
		return errors.Wrap(err, "ping")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("notary ping failed with %q", resp.Status)
	}
	return nil
}

func (r *notaryRepo) getClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: r.skipVerify,
			},
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}

func (r *notaryRepo) buildRoleURL(roleName role) (string, error) {
	err := validateRole(roleName)
	if err != nil {
		return "", err
	}
	path, err := url.Parse(fmt.Sprintf(tumAPIPattern, r.gun, roleName))
	if err != nil {
		return "", errors.Wrap(err, "building path for remote repo")
	}
	return r.url.ResolveReference(path).String(), nil
}

func (r *notaryRepo) getRole(roleName role, role interface{}, opts ...func() interface{}) error {
	maxResponseSize := r.maxResponseSize
	var testers []tester
	for _, opt := range opts {
		switch t := opt().(type) {
		case expectedSizeType:
			maxResponseSize = int64(t)
		case tester:
			testers = append(testers, t)
		}
	}
	roleURL, err := r.buildRoleURL(roleName)
	if err != nil {
		return errors.Wrap(err, "getting remote role")
	}
	client := r.getClient()
	resp, err := client.Get(roleURL)
	if err != nil {
		return errors.Wrap(err, "fetching role from remote repo")
	}
	defer resp.Body.Close()
	// clients must limit read sizes per tuf spec
	limitedReader := &io.LimitedReader{R: resp.Body, N: maxResponseSize + 1}

	if resp.StatusCode != http.StatusOK {
		// It's legitimate not to find roles in some circumstances
		if resp.StatusCode == http.StatusNotFound {
			return errNotFound
		}
		return errors.Wrap(err, "notary server error")
	}
	var buff bytes.Buffer
	read, err := io.Copy(&buff, limitedReader)
	if err != nil {
		return errors.Wrap(err, "reading response from notary")
	}
	if read > maxResponseSize {
		return errors.New("remote response size exceeds expected")
	}
	for _, ts := range testers {
		err = ts.test(buff.Bytes())
		if err != nil {
			return errors.Wrap(err, "validating response from notary")
		}
	}
	err = json.NewDecoder(&buff).Decode(role)
	if err != nil {
		return errors.Wrap(err, "parsing json returned from server")
	}
	return nil
}
