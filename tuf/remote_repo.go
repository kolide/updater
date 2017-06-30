package tuf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type remoteReaderSettings struct {
	gun             string
	url             string
	maxResponseSize int64
	client          *http.Client
	rootRole        *Root
	snapshotRole    *Snapshot
	localRootTarget *RootTarget
}

type remoteTargetReader struct {
	settings *remoteReaderSettings
	url      *url.URL
	seen     map[string]struct{}
	keys     map[keyID]Key
	roles    map[string]Role
}

func newRemoteTargetReader(settings *remoteReaderSettings) (*remoteTargetReader, error) {
	u, err := url.Parse(settings.url)
	if err != nil {
		return nil, errors.Wrap(err, "instantianting remote target reader")
	}
	rdr := &remoteTargetReader{
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

func (rdr *remoteTargetReader) read(delegate string) (*Targets, error) {
	if len(rdr.seen) > maxDelegationCount {
		return nil, errTooManyDelegates
	}
	// prevent cycles in target tree
	if _, ok := rdr.seen[delegate]; ok {
		return nil, errTargetSeen
	}
	rdr.seen[delegate] = struct{}{}
	path, err := url.Parse(fmt.Sprintf(tumAPIPattern, rdr.settings.gun, delegate))
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
	// get hashes and length for the target we're about to read
	fim, ok := rdr.settings.snapshotRole.Signed.Meta[role(delegate)]
	if !ok {
		return nil, errors.Errorf("fim data missing for %q", delegate)
	}
	inStream := io.LimitReader(resp.Body, fim.Length)
	var validated bytes.Buffer
	// verify file integrity
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
	err = verifySignatures(target.Signed, rdr.keys, target.Signatures, role.Threshold)
	if err != nil {
		return nil, errors.Wrapf(err, "signature validation failed for role %q", delegate)
	}
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

func (rdr *remoteTargetReader) compareToExistingTarget(delegate string, target *Targets) error {
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
	if time.Now().After(target.Signed.Expires) {
		return errFreezeAttack
	}
	return nil
}

func (rdr *remoteTargetReader) saveKeysForRoles(target *Targets) {
	for id, key := range target.Signed.Delegations.Keys {
		rdr.keys[id] = key
	}
	for _, delegate := range target.Signed.Delegations.Roles {
		rdr.roles[delegate.Name] = delegate.Role
	}
}

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

func (r *notaryRepo) targets(rdr roleReader, opts ...func() interface{}) (*RootTarget, error) {
	rootTarget, err := getTargetRole(rdr)
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

	resp, err := r.client.Get(roleURL)
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
