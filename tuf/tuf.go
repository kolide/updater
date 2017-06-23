package tuf

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/pkg/errors"
)

// Settings various parameters needed to find updates
type Settings struct {
	// LocalRepoPath is the directory where we will cache TUF roles. This
	// directory should be seeded with TUF role files with 0600 permissions.
	LocalRepoPath string
	// NotaryURL is the base URL of the notary server where we get new
	// keys and update information.  i.e. https://notary.kolide.co. Must use
	// https scheme.
	NotaryURL string
	// MirrorURL is the base URL where distribution packages are found and
	// downloaded. Must use https scheme.
	MirrorURL string
	// StagingPath is where new distribution packages are stored after they
	// have been validated.
	StagingPath string
	// InsecureSkipVerify if true, the client accepts unsigned certificates.  This
	// option should only be used for testing.
	InsecureSkipVerify bool
	// GUN Globally Unique Identifier, an ID used by Notary to identify
	// a repository. Typically in the form organization/reponame/platform
	GUN string
	// MaxResponseSize the maximum size of a get response.  Defaults to
	// 5 MB
	MaxResponseSize int64
	// TargetName is the name of the target to retreive. Typically this would
	// denote a version, like 'v2' or 'latest'
	TargetName targetNameType
	// Client is the one and only http client
	Client *http.Client
}

// Monitor manages state for TUF repositories.
type Monitor struct {
	settings *Settings
}

// New instantiatest and monitor which is used to detect and manage changes to
// the TUF repository.
func New(settings *Settings) *Monitor {
	if settings.Client == nil {
		settings.Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: settings.InsecureSkipVerify,
				},
				TLSHandshakeTimeout: 5 * time.Second,
			},
			Timeout: 5 * time.Second,
		}
	}
	m := &Monitor{
		settings: settings,
	}
	return m
}

// GetStagedPath returns a the staging path of a target if it needs to be updated. The
// target that will be checked is defined in settings.
// These packages are validated and obtained according to The Update Framework
// Spec https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
// Section 5.1 The Client Application
func (m *Monitor) GetStagedPath() (string, error) {
	if m.settings.MaxResponseSize == 0 {
		m.settings.MaxResponseSize = defaultMaxResponseSize
	}
	// check to see if Notary server is available
	notary, err := newNotaryRepo(m.settings)
	if err != nil {
		return "", errors.Wrap(err, "creating notary client")
	}
	err = notary.ping()
	if err != nil {
		return "", errors.Wrap(err, "pinging notary server failed")
	}
	localRepo, err := newLocalRepo(m.settings.LocalRepoPath)
	if err != nil {
		return "", errors.New("creating local tuf role repo")
	}
	// store intermediate state until all validation succeeds, then write
	// changed roles to non-volitile storage
	state := newRepoMan(localRepo, notary, m.settings, notary.client)
	stagedPath, err := state.refresh()
	if err != nil {
		return "", errors.Wrap(err, "getting paths for staged packages")
	}
	// IF all operations are successful, we write new TUF repository to
	// persistent storage.  This will be our baseline state for the next check
	// for updates.
	tag := getTag()
	err = state.save(tag)
	if err != nil {
		return "", errors.Wrap(err, "unable to save tuf repo state")
	}
	return stagedPath, nil
}

// getTag a timestamp based moniker
func getTag() string {
	return time.Now().Format(time.Now().Format(filetimeFormat))
}

type repoMan struct {
	settings  *Settings
	repo      persistentRepo
	notary    remoteRepo
	root      *Root
	timestamp *Timestamp
	snapshot  *Snapshot
	targets   *Targets
	client    *http.Client
}

func newRepoMan(repo persistentRepo, notary remoteRepo, settings *Settings, client *http.Client) *repoMan {
	return &repoMan{
		settings: settings,
		repo:     repo,
		notary:   notary,
		client:   client,
	}
}

func (rs *repoMan) save(backupTag string) (err error) {
	defer func() {
		if err != nil {
			rs.restoreRoles(backupTag)
			return
		}
		// clean up backup files
		err = rs.deleteBackupRoles(backupTag)
	}()
	var buff []byte
	roles := []struct {
		cached interface{}
		name   role
	}{
		{rs.root, roleRoot},
		{rs.timestamp, roleTimestamp},
		{rs.snapshot, roleSnapshot},
		{rs.targets, roleTargets},
	}
	err = rs.backupRoles(backupTag)
	if err != nil {
		return errors.Wrap(err, "local repo backup failed")
	}
	for _, r := range roles {
		if reflect.ValueOf(r.cached).IsNil() {
			err = errors.Errorf("can't save %q, cached role is nil", r)
			break
		}
		buff, err = cjson.MarshalCanonical(r.cached)
		if err != nil {
			err = errors.Wrap(err, "marshalling role failed")
			break
		}
		err = rs.saveRole(r.name, buff)
		if err != nil {
			err = errors.Wrap(err, "saving role")
			break
		}
	}
	return err
}

func (rs *repoMan) backupRoles(tag string) error {
	roles := []role{roleRoot, roleTargets, roleSnapshot, roleTimestamp}
	for _, r := range roles {
		source := path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.json", r))
		destination := path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.%s.json", r, tag))
		err := os.Rename(source, destination)
		if err != nil {
			return errors.Wrap(err, "backing up role")
		}
	}
	return nil
}

func (rs *repoMan) restoreRoles(tag string) error {
	roles := []role{roleRoot, roleTargets, roleSnapshot, roleTimestamp}
	for _, r := range roles {
		destination := path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.json", r))
		source := path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.%s.json", r, tag))
		_, err := os.Stat(source)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errors.Wrap(err, "problem restoring roles")
		}
		err = os.Rename(source, destination)
		if err != nil {
			return errors.Wrap(err, "moving backup role")
		}
	}
	return nil
}

// If local TUF repo was successfully updated we want to get rid of backup files
// that they don't take up drive space.
func (rs *repoMan) deleteBackupRoles(tag string) error {
	roles := []role{roleRoot, roleTargets, roleSnapshot, roleTimestamp}
	for _, r := range roles {
		backupFilePath := path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.%s.json", r, tag))
		fs, err := os.Stat(backupFilePath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errors.Wrap(err, "checking existance of role backup file")
		}
		if fs.Mode().IsRegular() {
			err = os.Remove(backupFilePath)
			if err != nil {
				return errors.Wrap(err, "removing role backup file")
			}
		}
	}
	return nil
}

func (rs *repoMan) saveRole(r role, js []byte) error {
	fs, err := os.OpenFile(path.Join(rs.settings.LocalRepoPath, fmt.Sprintf("%s.json", r)), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "saving role file")
	}
	defer fs.Close()
	written, err := io.Copy(fs, bytes.NewBuffer(js))
	if err != nil {
		return errors.Wrap(err, "writing role to open file")
	}
	if written != int64(len(js)) {
		return errors.New("not all of the role was written to file")
	}
	return nil
}

// refresh gets the current metadata from the notary repository and performs
// requisite checks and validations as specified in the TUF spec section 5. Note
// that we expect that we do not used consistent snapshots and delegations are
// not supported because for our purposes, both are unnecessary.
// See https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
func (rs *repoMan) refresh() (string, error) {
	root, err := rs.refreshRoot()
	if err != nil {
		return "", errors.Wrap(err, "refreshing root")
	}
	// cache the current root
	rs.root = root
	timestamp, err := rs.refreshTimestamp(root)
	if err != nil {
		return "", errors.Wrap(err, "refreshing timestamp")
	}
	rs.timestamp = timestamp
	snapshot, err := rs.refreshSnapshot(root, timestamp)
	if err != nil {
		return "", errors.Wrap(err, "refreshing snapshot")
	}
	rs.snapshot = snapshot
	targets, stagingPath, err := rs.refreshTargets(root, snapshot)
	if err != nil {
		return "", errors.Wrap(err, "refreshing targets")
	}
	rs.targets = targets
	return stagingPath, nil
}

func (rs *repoMan) refreshRoot() (*Root, error) {
	// get root from local
	root, err := rs.repo.root()
	if err != nil {
		return nil, errors.Wrap(err, "refresh root")
	}
	for {
		nextRoot, err := rs.notary.root(version(root.Signed.Version + 1))
		if err == errNotFound {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "reading root version from notary")
		}
		// check signatures from current root, and next root to establish chain of trust
		keymap := keymapForSignatures(root)
		err = rs.verifySignatures(nextRoot.Signed, keymap, root.Signatures, root.Signed.Roles[roleRoot].Threshold)
		if err != nil {
			return nil, errors.Wrap(err, " previous root signature verification failed")
		}
		keymap = keymapForSignatures(nextRoot)
		err = rs.verifySignatures(nextRoot.Signed, keymap, nextRoot.Signatures, nextRoot.Signed.Roles[roleRoot].Threshold)
		if err != nil {
			return nil, errors.Wrap(err, "root signature verification failed")
		}
		// both sets of validation succeeded set current root to next root
		root = nextRoot
	}
	return root, nil
}

func (rs *repoMan) getKeys(r *Root, sigs []Signature) map[keyID]Key {
	result := make(map[keyID]Key)
	for _, sig := range sigs {
		k, ok := r.keys()[sig.KeyID]
		if ok {
			result[sig.KeyID] = k
		}
	}
	return result
}

func (rs *repoMan) refreshTimestamp(root *Root) (*Timestamp, error) {
	previous, err := rs.repo.timestamp()
	if err != nil {
		return nil, errors.Wrap(err, "fetching local timestamp")
	}

	remote, err := rs.notary.timestamp()
	if err != nil {
		return nil, errors.Wrap(err, "fetching remote timestamp")
	}

	// check signature of the remote timestamp to make sure it hasn't been
	// comprimised
	keys := rs.getKeys(root, remote.Signatures)
	threshold := root.Signed.Roles[roleTimestamp].Threshold
	err = rs.verifySignatures(remote.Signed, keys, remote.Signatures, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "signature validation failed for timestamp")
	}
	// check for rollback attack
	if previous.Signed.Version > remote.Signed.Version {
		return nil, errors.Errorf("previous timestamp version %q is after current timestamp version %q", previous.Signed.Version, remote.Signed.Version)
	}
	// check for freeze attack
	if time.Now().After(remote.Signed.Expires) {
		return nil, errors.New("current timestamp expired")
	}
	return remote, nil
}

func (rs *repoMan) refreshSnapshot(root *Root, timestamp *Timestamp) (*Snapshot, error) {
	previous, err := rs.repo.snapshot()
	if err != nil {
		return nil, errors.Wrap(err, "fetching local snapshot")
	}
	fim, ok := timestamp.Signed.Meta[roleSnapshot]
	if !ok {
		return nil, errors.New("expected snapshot metadata was missing from timestamp role")
	}
	// hashes and length from timestamp role are used to insure the
	// the integrity of the snapshot role
	var ssOpts []func() interface{}
	ssOpts = append(ssOpts, expectedSize(int64(fim.Length)))
	hash, ok := fim.Hashes[hashSHA256]
	if ok {
		ssOpts = append(ssOpts, testSHA256(hash))
	}
	hash, ok = fim.Hashes[hashSHA512]
	if ok {
		ssOpts = append(ssOpts, testSHA512(hash))
	}
	current, err := rs.notary.snapshot(ssOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "fetching remote snapshot")
	}
	keys := rs.getKeys(root, current.Signatures)
	threshold := root.Signed.Roles[roleSnapshot].Threshold
	err = rs.verifySignatures(current.Signed, keys, current.Signatures, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "signature validation failed for snapshot")
	}
	if previous.Signed.Version > current.Signed.Version {
		return nil, errors.Errorf("previous snapshot version %q is after current version %q",
			previous.Signed.Version,
			current.Signed.Version,
		)
	}
	if time.Now().After(current.Signed.Expires) {
		return nil, errors.New("current snapshot expired")
	}

	return current, nil
}

func (rs *repoMan) refreshTargets(root *Root, snapshot *Snapshot) (*Targets, string, error) {
	previous, err := rs.repo.targets()
	if err != nil {
		return nil, "", errors.Wrap(err, "fetching local targets")
	}
	fim, ok := snapshot.Signed.Meta[roleTargets]
	if !ok {
		return nil, "", errors.New("missing target metadata in snapshot")
	}
	var opts []func() interface{}
	opts = append(opts, expectedSize(int64(fim.Length)))
	hash, ok := fim.Hashes[hashSHA256]
	if ok {
		opts = append(opts, testSHA256(hash))
	}
	hash, ok = fim.Hashes[hashSHA512]
	if ok {
		opts = append(opts, testSHA512(hash))
	}
	current, err := rs.notary.targets(opts...)
	if err != nil {
		return nil, "", errors.Wrap(err, "retrieving timestamp from notary")
	}
	keys := rs.getKeys(root, current.Signatures)
	threshold := root.Signed.Roles[roleTargets].Threshold
	err = rs.verifySignatures(current.Signed, keys, current.Signatures, threshold)
	if err != nil {
		return nil, "", errors.Wrap(err, "signature verification for targets failed")
	}
	if previous.Signed.Version > current.Signed.Version {
		return nil, "", errors.New("previous target has a version later than the current target")
	}
	if time.Now().After(current.Signed.Expires) {
		return nil, "", errors.New("current targets expired")
	}

	var stagedPath string
	if current.Signed.Version > previous.Signed.Version {
		stagedPath, err = rs.stageTarget(current.Signed.Targets)
		if err != nil {
			return nil, "", errors.Wrap(err, "staging targets")
		}
	}
	return current, stagedPath, nil
}

func (rs *repoMan) stageTarget(tgts map[targetNameType]FileIntegrityMeta) (string, error) {
	fim, ok := tgts[rs.settings.TargetName]
	if !ok {
		return "", errors.Errorf("No such target %q in %q", rs.settings.TargetName, rs.settings.GUN)
	}
	stagePath, err := rs.downloadTarget(rs.client, rs.settings.TargetName, &fim)
	if err != nil {
		return "", errors.Wrap(err, "downloading target")
	}
	return stagePath, nil
}

// download target from mirror, if it passes validation write it to staging and cache
// the location where it was written
func (rs *repoMan) downloadTarget(client *http.Client, target targetNameType, fim *FileIntegrityMeta) (string, error) {
	// we expect our mirrored distribution targets to be located
	// at https://mirror.com/gun/targetname
	mirrorURL, err := url.Parse(fmt.Sprintf("%s/%s/%s", rs.settings.MirrorURL, rs.settings.GUN, target))
	if err != nil {
		return "", errors.Wrap(err, "building url to download target")
	}
	request, err := http.NewRequest(http.MethodGet, mirrorURL.String(), nil)
	if err != nil {
		return "", errors.Wrap(err, "creating target request")
	}
	// Dissallow caching because if we are making this call, we know that the target
	// has changed and we want to make sure we get the data from the mirror, not
	// from cache.
	request.Header.Add(cacheControl, cachePolicyNoStore)
	resp, err := client.Do(request)
	if err != nil {
		return "", errors.Wrap(err, "fetching target from mirror")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("get target returned %q", resp.Status)
	}
	var buff bytes.Buffer
	readFromMirror, err := io.Copy(&buff, resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading target from mirror")

	}

	err = fim.verify(buff.Bytes(), readFromMirror)
	if err != nil {
		return "", errors.Wrap(err, "target verification failed")
	}
	// our target is valid so write it to staging
	stagingPath := path.Join(rs.settings.StagingPath, string(target))
	// find out of any subdirectories need to be created
	fullDir := filepath.Dir(stagingPath)
	fs, err := os.Stat(fullDir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(fullDir, 0755)
		if err != nil {
			return "", errors.Wrap(err, "making staging directory")
		}
	}
	// if the path exists make sure it's a directory
	if fs != nil && !fs.IsDir() {
		return "", errors.Errorf("staging location %q is not a directory", fullDir)
	}

	out, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", errors.Wrap(err, "creating staging file")
	}
	defer out.Close()
	writtenToFile, err := io.Copy(out, &buff)
	if err != nil {
		return "", errors.Wrap(err, "writing target file to staging")
	}
	if writtenToFile != readFromMirror {
		return "", errors.Errorf("file write incomplete for %q", target)
	}
	return stagingPath, nil
}

func (rs *repoMan) verifySignatures(role marshaller, keys map[keyID]Key, sigs []Signature, threshold int) error {
	// just in case, make sure threshold is not zero as this would mean we're not checking any sigs
	if threshold <= 0 {
		return errors.New("signature threshold must be greater than zero")
	}
	signed, err := role.canonicalJSON()
	if err != nil {
		return errors.Wrap(err, "getting digest for sig verification")
	}
	verified := 0
	for _, sig := range sigs {
		key, ok := keys[sig.KeyID]
		if !ok {
			continue
		}
		verifier, err := newVerifier(sig.SigningMethod)
		if err != nil {
			return errors.Wrap(err, "getting signature verifier")
		}
		err = verifier.verify(signed, &key, &sig)
		// Some of the verifications might fail, if that happens, jump to
		// the top of the loop and try with another signature
		if err == errSignatureCheckFailed {
			continue
		}
		if err != nil {
			return errors.Wrap(err, "unexpected verfication error")
		}
		// record successful sig verification
		verified++
		if verified == threshold {
			// yay! we validated enough sigs to be successful
			return nil
		}
	}
	// boo! we did not get meet the threshold
	return errSignatureThresholdNotMet
}

func keymapForSignatures(ks signedkeyed) map[keyID]Key {
	result := make(map[keyID]Key)
	for _, sig := range ks.sigs() {
		k, ok := ks.keys()[sig.KeyID]
		if ok {
			result[sig.KeyID] = k
		}
	}
	return result
}
