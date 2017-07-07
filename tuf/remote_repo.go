package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/WatchBeam/clock"
	"github.com/pkg/errors"
	"github.com/y0ssar1an/q"
)

type notaryTargetFetcherSettings struct {
	gun             string
	url             string
	maxResponseSize int64
	client          *http.Client
	rootRole        *Root
	snapshotRole    *Snapshot
	localRootTarget *RootTarget
	clock           clock.Clock
}

type notaryTargetFetcher struct {
	settings *notaryTargetFetcherSettings
	url      *url.URL
	seen     map[string]struct{}
	keys     map[keyID]Key
	roles    map[string]Role
}

func newNotaryTargetFetcher(settings *notaryTargetFetcherSettings) (*notaryTargetFetcher, error) {
	u, err := url.Parse(settings.url)
	if err != nil {
		return nil, errors.Wrap(err, "instantianting remote target reader")
	}
	rdr := &notaryTargetFetcher{
		settings: settings,
		url:      u,
		seen:     make(map[string]struct{}),
		keys:     make(map[keyID]Key),
		roles:    make(map[string]Role),
	}
	targetRole := settings.rootRole.Signed.Roles[roleTargets]
	for _, id := range targetRole.KeyIDs {
		key, ok := settings.rootRole.Signed.Keys[keyID(id)]
		if !ok {
			return nil, errors.New("no key present for key id")
		}
		rdr.keys[keyID(id)] = key
	}
	rdr.roles[string(roleTargets)] = targetRole
	return rdr, nil
}

// 5. **Verify the desired target against its targets metadata.**
func (rdr *notaryTargetFetcher) fetch(delegate string) (*Targets, error) {
	// 	4.5.1. If this role has been visited before, then skip this role (so that
	// cycles in the delegation graph are avoided).
	// Otherwise, if an application-specific maximum number of roles have been
	// visited, then go to step 5 (so that attackers cannot cause the client to
	// waste excessive bandwidth or time).
	if len(rdr.seen) > maxDelegationCount {
		return nil, errTooManyDelegates
	}
	// prevent cycles in target tree
	if _, ok := rdr.seen[delegate]; ok {
		return nil, errTargetSeen
	}
	rdr.seen[delegate] = struct{}{}
	path, err := url.Parse(fmt.Sprintf(tufAPIFormat, rdr.settings.gun, delegate))
	if err != nil {
		return nil, errors.Wrap(err, "bad url in remote target read")
	}
	roleLocation := rdr.url.ResolveReference(path).String()
	resp, err := rdr.settings.client.Get(roleLocation)
	if err != nil {
		return nil, errors.Wrap(err, "fetching remote target")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("notary server request status %q", resp.Status)
	}
	// get hashes and length from snapshot for step 4.1
	fim, ok := rdr.settings.snapshotRole.Signed.Meta[role(delegate)]
	if !ok {
		return nil, errors.Errorf("fim data missing for %q", delegate)
	}
	inStream := io.LimitReader(resp.Body, fim.Length)
	var validated bytes.Buffer
	// 4.1. **Check against snapshot metadata.** The hashes (if any), and version
	// number of this metadata file MUST match the snapshot metadata. This is
	// done, in part, to prevent a mix-and-match attack by man-in-the-middle
	// attackers.
	err = fim.verify(io.TeeReader(inStream, &validated))
	if err != nil {
		return nil, errors.Wrapf(err, "file integrity checks failed for %q", delegate)
	}
	var target Targets
	err = json.NewDecoder(&validated).Decode(&target)
	if err != nil {
		return nil, errors.Wrap(err, "target json could not be decoded")
	}
	role, ok := rdr.roles[delegate]
	if !ok {
		return nil, errors.Errorf("unable to find role info for %q", delegate)
	}
	// 4.5.2.1. If the current delegation is a multi-role delegation, recursively
	// visit each role, and check that each has signed exactly the same non-custom
	// metadata (i.e., length and hashes) about the target (or the lack of any
	// such metadata).
	err = verifySignatures(target.Signed, rdr.keys, target.Signatures, role.Threshold)
	if err != nil {
		return nil, errors.Wrapf(err, "signature validation failed for role %q", delegate)
	}
	// Do further checks, validating against previous version.
	err = rdr.compareToExistingTarget(delegate, &target)
	if err != nil {
		return nil, errors.Wrapf(err, "comparing local delegate to notary delegate %q", delegate)
	}
	// we have a valid target at so save it's keys to validate the next target
	// because we are doing pre-order traversal the parent target's keys will
	// always be available to check the signatures of children
	rdr.saveKeysForRoles(&target)
	return &target, nil
}

func (rdr *notaryTargetFetcher) compareToExistingTarget(delegate string, target *Targets) error {
	// check for previous delegation, it may not exist if a new delegation was created
	previous, ok := rdr.settings.localRootTarget.targetLookup[delegate]
	if !ok {
		return nil
	}
	// 4.3. **Check for a rollback attack.** The version number of the previous
	// targets metadata file, if any, MUST be less than or equal to the version
	// number of this targets metadata file.
	if previous.Signed.Version > target.Signed.Version {
		return errRollbackAttack
	}
	// 4.4. **Check for a freeze attack.** The latest known time should be lower
	// than the expiration timestamp in this metadata file.
	if rdr.settings.clock.Now().After(target.Signed.Expires) {
		return errFreezeAttack
	}
	return nil
}

func (rdr *notaryTargetFetcher) saveKeysForRoles(target *Targets) {
	for id, key := range target.Signed.Delegations.Keys {
		rdr.keys[id] = key
	}
	for _, delegate := range target.Signed.Delegations.Roles {
		rdr.roles[delegate.Name] = delegate.Role
	}
}

type tester interface {
	test([]byte) error
}

func (r *notaryRepo) root(opts ...repoOption) (*Root, error) {
	var optVal repoOptions
	for _, opt := range opts {
		opt(&optVal)
	}
	roleVal := roleRoot
	if optVal.rootOptions.version > 0 {
		roleVal = role(fmt.Sprintf("%d.%s", optVal.rootOptions.version, roleRoot))
	}
	var root Root
	err := r.getRole(roleVal, &root)
	if err != nil {
		return nil, err
	}
	return &root, nil
}

func (r *notaryRepo) targets(fetcher roleFetcher, opts ...repoOption) (*RootTarget, error) {
	rootTarget, err := targetTreeBuilder(fetcher)
	if err != nil {
		return nil, errors.Wrap(err, "getting remote target role")
	}
	return rootTarget, nil
}

func (r *notaryRepo) timestamp() (*Timestamp, error) {
	var timestamp Timestamp
	err := r.getRole(roleTimestamp, &timestamp)
	if err != nil {
		return nil, err
	}
	return &timestamp, nil
}

func (r *notaryRepo) snapshot(opts ...repoOption) (*Snapshot, error) {
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

	resp, err := r.client.Get(pingURL)
	if err != nil {
		return errors.Wrap(err, "ping")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("notary ping failed with %q", resp.Status)
	}
	return nil
}

func (r *notaryRepo) buildRoleURL(roleName role) (string, error) {
	err := validateRole(roleName)
	if err != nil {
		return "", err
	}
	path, err := url.Parse(fmt.Sprintf(tufAPIFormat, r.gun, roleName))
	if err != nil {
		return "", errors.Wrap(err, "building path for remote repo")
	}
	return r.url.ResolveReference(path).String(), nil
}

func (r *notaryRepo) getRole(roleName role, role interface{}, opts ...repoOption) error {
	maxResponseSize := r.maxResponseSize
	var testers []tester
	var optVal repoOptions
	for _, opt := range opts {
		opt(&optVal)
	}
	if optVal.roleOptions.expectedLength > 0 {
		maxResponseSize = optVal.roleOptions.expectedLength
	}
	if len(optVal.roleOptions.tests) > 0 {
		testers = optVal.roleOptions.tests
	}
	roleURL, err := r.buildRoleURL(roleName)
	if err != nil {
		return errors.Wrap(err, "getting remote role")
	}
	q.Q("max size >> ", maxResponseSize)
	resp, err := r.client.Get(roleURL)
	if err != nil {
		return errors.Wrap(err, "fetching role from remote repo")
	}
	defer resp.Body.Close()
	// Read up to a number of bytes. The can be specified from the previous role,
	// or in the case of root no more than defaultMaxResponseSize
	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	if resp.StatusCode != http.StatusOK {
		// It's legitimate not to find roles in some circumstances
		if resp.StatusCode == http.StatusNotFound {
			return errNotFound
		}
		return errors.Wrap(err, "notary server error")
	}
	var buff bytes.Buffer
	_, err = io.Copy(&buff, limitedReader)
	if err != nil {
		return errors.Wrap(err, "reading response from notary")
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
