package tuf

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type roleVersion int

// pass optional role version to root()
func version(v int) func() interface{} {
	return func() interface{} {
		return roleVersion(v)
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

func (r *notaryRepo) targets() (*Targets, error) {
	var targets Targets
	err := r.getRole(roleTargets, &targets)
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

func (r *notaryRepo) snapshot() (*Snapshot, error) {
	var snapshot Snapshot
	err := r.getRole(roleSnapshot, &snapshot)
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

func (r *notaryRepo) getRole(roleName role, role interface{}) error {
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
	if resp.StatusCode != http.StatusOK {
		// It's legitimate not to find roles in some circumstances
		if resp.StatusCode == http.StatusNotFound {
			return errNotFound
		}
		return errors.Wrap(err, "notary server error")
	}
	err = json.NewDecoder(resp.Body).Decode(role)
	if err != nil {
		return errors.Wrap(err, "parsing json returned from server")
	}
	return nil
}
