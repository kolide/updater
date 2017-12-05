package tuf

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/pkg/errors"
)

var (
	errRollbackAttack         = errors.New("role version is greater than previous role version")
	errFreezeAttack           = errors.New("current time is after role expiration timestamp")
	errUnsupportedHash        = errors.New("unsupported hash alogorithm")
	errHashIncorrect          = errors.New("file hash does not match")
	errLengthIncorrect        = errors.New("file length incorrect")
	errNoSuchTarget           = errors.New("no such target")
	errNotFound               = errors.New("resource does not exist")
	errMaxDelegationsExceeded = errors.New("too many delegations")
	errTargetSeen             = errors.New("target already seen in tree")
	errFailedIntegrityCheck   = errors.New("target file fails integrity check")
	errTooManyDelegates       = errors.Errorf("number of delegates exceeds max %d", maxDelegationCount)
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
	// GUN Globally Unique Identifier, an ID used by Notary to identify
	// a repository. Typically in the form organization/reponame/platform
	GUN string
}

func (s *Settings) verify() error {
	err := validatePath(s.LocalRepoPath)
	if err != nil {
		return errors.Wrap(err, "verifying local repo path")
	}
	if s.GUN == "" {
		return errors.New("GUN can't be empty")
	}
	_, err = validateURL(s.NotaryURL)
	if err != nil {
		return errors.Wrap(err, "remote repo url validation")
	}
	_, err = validateURL(s.MirrorURL)
	if err != nil {
		return errors.Wrap(err, "mirror url validation")
	}
	return nil
}

type repoMan struct {
	settings  *Settings
	repo      persistentRepo
	notary    remoteRepo
	root      *Root
	timestamp *Timestamp
	snapshot  *Snapshot
	targets   *RootTarget
	client    *http.Client
	clock     clock.Clock
	backupAge time.Duration
}

func (rs *repoMan) save() error {

	ss := saveSettings{
		tufRepositoryRootDir: rs.settings.LocalRepoPath,
		backupAge:            rs.backupAge,
		rootRole:             rs.root,
		timestampRole:        rs.timestamp,
		snapshotRole:         rs.snapshot,
		targetsRole:          rs.targets,
	}
	if err := saveTufRepository(&ss); err != nil {
		return errors.Wrap(err, "failed to save tuf repo")
	}
	return nil
}

type refreshResponse struct {
	latest bool
	err    error
}

func (rs *repoMan) refresh() (bool, error) {
	root, err := rs.refreshRoot()
	if err != nil {
		return false, errors.Wrap(err, "refreshing root")
	}
	rs.root = root
	timestamp, err := rs.refreshTimestamp(root)
	if err != nil {
		return false, errors.Wrap(err, "refreshing timestamp")
	}
	rs.timestamp = timestamp
	snapshot, err := rs.refreshSnapshot(root, timestamp)
	if err != nil {
		return false, errors.Wrap(err, "refreshing snapshot")
	}
	rs.snapshot = snapshot
	targets, changed, err := rs.refreshTargets(root, snapshot)
	if err != nil {
		return false, errors.Wrap(err, "refreshing targets")
	}
	rs.targets = targets
	if err := rs.save(); err != nil {
		return false, errors.Wrap(err, "saving new tuf repo")
	}
	return len(changed) == 0, nil
}

func newRepoMan(repo persistentRepo, notary remoteRepo, settings *Settings, client *http.Client, backupAge time.Duration, k clock.Clock) *repoMan {
	man := &repoMan{
		settings:  settings,
		repo:      repo,
		notary:    notary,
		client:    client,
		clock:     k,
		backupAge: backupAge,
	}
	return man
}

// Root role processing TUF spec section 5.1.0 through 5.1.1.9
func (rs *repoMan) refreshRoot() (*Root, error) {
	// 0. **Load the previous root metadata file.** We assume that a good, trusted
	// copy of this file was shipped with the package manager / software updater
	// using an out-of-band process.
	root, err := rs.repo.root()
	if err != nil {
		return nil, errors.Wrap(err, "refresh root")
	}
	// 	0.1. **Check signatures.** The previous root metadata file MUST have been
	// signed by a threshold of keys specified in the previous root metadata file.
	//
	// 	0.2. Note that the expiration of the previous root metadata file does not
	// matter, because we will attempt to update it in the next step.
	keymap := keymapForSignatures(root)
	err = verifySignatures(root.Signed, keymap, root.Signatures, root.Signed.Roles[roleRoot].Threshold)
	if err != nil {
		return nil, errors.Wrap(err, "validating existing root")
	}
	// 	1. **Update the root metadata file.** Since it may now be signed using
	// entirely different keys, the client must somehow be able to establish a
	// trusted line of continuity to the latest set of keys (see Section 6.1). To
	// do so, the client MUST download intermediate root metadata files, until the
	// latest available one is reached.
	//
	// 1.1. Let N denote the version number of the previous root metadata file.
	//
	for {
		// 1.2. **Try downloading version N+1 of the root metadata file**, up to some
		// X number of bytes (because the size is unknown). The value for X is set by
		// the authors of the application using TUF. For example, X may be tens of
		// kilobytes. The filename used to download the root metadata file is of the
		// fixed form VERSION.FILENAME.EXT (e.g., 42.root.json). If this file is not
		// available, then go to step 1.8.
		nextRoot, err := rs.notary.root(withRootVersion(root.Signed.Version + 1))
		if err == errNotFound {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "reading root version from notary")
		}
		// 1.3. **Check signatures.** Version N+1 of the root metadata file MUST have
		// been signed by: (1) a threshold of keys specified in the previous root
		// metadata file (version N), and (2) a threshold of keys specified in the
		// current root metadata file (version N+1).
		keymap := keymapForSignatures(root)
		err = verifySignatures(nextRoot.Signed, keymap, nextRoot.Signatures, root.Signed.Roles[roleRoot].Threshold)
		if err != nil {
			return nil, errors.Wrap(err, " previous root signature verification failed")
		}
		keymap = keymapForSignatures(nextRoot)
		err = verifySignatures(nextRoot.Signed, keymap, nextRoot.Signatures, nextRoot.Signed.Roles[roleRoot].Threshold)
		if err != nil {
			return nil, errors.Wrap(err, "root signature verification failed")
		}
		// 1.4. **Check for a rollback attack.** The version number of the previous
		// root metadata file must be less than or equal to the version number of this
		// root metadata file. Effectively, this means checking that the version
		// number signed in the current root metadata file is indeed N+1.
		// both sets of validation succeeded set current root to next root
		if root.Signed.Version > nextRoot.Signed.Version {
			return nil, errRollbackAttack
		}
		// 1.6. Set the previous to the current root metadata file.
		root = nextRoot
	}
	// 	1.8. **Check for a freeze attack.** The latest known time should be lower
	// than the expiration timestamp in the current root metadata file.
	if time.Now().After(root.Signed.Expires) {
		return nil, errFreezeAttack
	}
	// Note for section 5.1.1.9 we always replace the target/snapshot roles
	// with version from notary
	return root, nil
}

// Timestamp role processing section 5.2 through 5.2.3 in the TUF spec.
func (rs *repoMan) refreshTimestamp(root *Root) (*Timestamp, error) {
	// 	2. **Download the timestamp metadata file**, up to Y number of bytes
	// (because the size is unknown.) The value for Y is set by the authors of the
	// application using TUF. For example, Y may be tens of kilobytes. The
	// filename used to download the timestamp metadata file is of the fixed form
	// FILENAME.EXT (e.g., timestamp.json).
	remote, err := rs.notary.timestamp()
	if err != nil {
		return nil, errors.Wrap(err, "fetching remote timestamp")
	}
	// 2.1. **Check signatures.** The timestamp metadata file must have been
	// signed by a threshold of keys specified in the root metadata file.
	keys := getKeys(root, remote.Signatures)
	threshold := root.Signed.Roles[roleTimestamp].Threshold
	err = verifySignatures(remote.Signed, keys, remote.Signatures, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "signature validation failed for timestamp")
	}
	previous, err := rs.repo.timestamp()
	if err != nil {
		return nil, errors.Wrap(err, "fetching local timestamp")
	}
	// 2.2. **Check for a rollback attack.** The version number of the previous
	// timestamp metadata file, if any, must be less than or equal to the version
	// number of this timestamp metadata file.
	if previous.Signed.Version > remote.Signed.Version {
		return nil, errRollbackAttack
	}
	// 2.3. **Check for a freeze attack.** The latest known time should be lower
	// than the expiration timestamp in this metadata file.
	if rs.clock.Now().After(remote.Signed.Expires) {
		return nil, errFreezeAttack
	}
	return remote, nil
}

// Snapshot processing section 5.3 through 5.3.3.2 in the TUF spec
func (rs *repoMan) refreshSnapshot(root *Root, timestamp *Timestamp) (*Snapshot, error) {
	// 3. **Download and check the snapshot metadata file**, up to the number of
	// bytes specified in the timestamp metadata file.
	// If consistent snapshots are not used (see Section 7), then the filename
	// used to download the snapshot metadata file is of the fixed form
	// FILENAME.EXT (e.g., snapshot.json).
	// Otherwise, the filename is of the form VERSION.FILENAME.EXT (e.g.,
	// 42.snapshot.json), where VERSION is the version number of the snapshot
	// metadata file listed in the timestamp metadata file.  In either case,
	// the client MUST write the file to non-volatile storage as
	// FILENAME.EXT.
	//
	// 3.1. **Check against timestamp metadata.** The hashes, and version number
	// of this metadata file MUST match the timestamp metadata.
	fim, ok := timestamp.Signed.Meta[roleSnapshot]
	if !ok {
		return nil, errors.New("expected snapshot metadata was missing from timestamp role")
	}
	var ssOpts []repoOption
	ssOpts = append(ssOpts, withRoleExpectedLength(fim.Length))
	for algo, expectedHash := range fim.Hashes {
		hashTest, err := newHashInfo(algo, []byte(expectedHash))
		if err != nil {
			return nil, errors.Wrap(err, "refresh snapshot collecting hash tests")
		}
		ssOpts = append(ssOpts, withRoleTest(hashTest))
	}
	current, err := rs.notary.snapshot(ssOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "fetching remote snapshot")
	}
	// 3.2. **Check signatures.** The snapshot metadata file MUST have been signed
	// by a threshold of keys specified in the previous root metadata file.
	keys := getKeys(root, current.Signatures)
	threshold := root.Signed.Roles[roleSnapshot].Threshold
	err = verifySignatures(current.Signed, keys, current.Signatures, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "signature validation failed for snapshot")
	}
	previous, err := rs.repo.snapshot()
	if err != nil {
		return nil, errors.Wrap(err, "fetching local snapshot")
	}
	// 3.3. **Check for a rollback attack.**
	if previous.Signed.Version > current.Signed.Version {
		return nil, errRollbackAttack
	}

	// 3.3.3. The version number of the targets metadata file, and all delegated
	// targets metadata files (if any), in the trusted snapshot metadata file,
	// if any, MUST be less than or equal to its version number in the new snapshot
	// metadata file. Furthermore, any targets metadata filename that was listed
	// in the trusted snapshot metadata file, if any, MUST continue to be listed
	// in the new snapshot metadata file.
	trustedTargets, err := rs.repo.targets(&localTargetFetcher{rs.repo.baseDir()})
	if err != nil {
		return nil, errors.Wrap(err, "fetching trusted targets from snapshot")
	}

	if trustedTargets.Signed.Version > current.Signed.Version {
		return nil, errRollbackAttack
	}

	for role, target := range trustedTargets.targetLookup {
		if target.Signed.Version > current.Signed.Version {
			return nil, errors.Wrapf(errRollbackAttack, "role %s", role)
		}
	}

	// 3.4. **Check for a freeze attack.** The latest known time should be lower
	// than the expiration timestamp in this metadata file.
	if rs.clock.Now().After(current.Signed.Expires) {
		return nil, errFreezeAttack
	}
	return current, nil
}

// Targets processing section 5.4 through 5.5.2 in the TUF spec. It returns
// the latest targets and a list of any paths that have changed
func (rs *repoMan) refreshTargets(root *Root, snapshot *Snapshot) (*RootTarget, []string, error) {
	// 4. **Download and check the top-level targets metadata file**, up to either
	// the number of bytes specified in the snapshot metadata file, or some
	// Z number of bytes. The value for Z is set by the authors of the application
	// using TUF. For example, Z may be tens of kilobytes.
	// If consistent snapshots are not used (see Section 7), then the filename
	// used to download the targets metadata file is of the fixed form
	// FILENAME.EXT (e.g., targets.json).
	// Otherwise, the filename is of the form VERSION.FILENAME.EXT (e.g.,
	// 42.targets.json), where VERSION is the version number of the targets
	// metadata file listed in the snapshot metadata file.
	// In either case, the client MUST write the file to non-volatile storage as
	// FILENAME.EXT.
	// 	4.1. **Check against snapshot metadata.** The hashes (if any), and version
	// number of this metadata file MUST match the snapshot metadata. This is
	// done, in part, to prevent a mix-and-match attack by man-in-the-middle
	// attackers.
	previous, err := rs.repo.targets(&localTargetFetcher{rs.repo.baseDir()})
	if err != nil {
		return nil, nil, errors.Wrap(err, "fetching local targets")
	}
	// the fetcher we are creating will be called by targetTreeBuilder each time it needs to
	// download a child target while doing a preorder depth first traversal.
	// TUF validations occur each time a target is read. See targetFetcher.
	settings := &notaryTargetFetcherSettings{
		gun:             rs.settings.GUN,
		url:             rs.settings.NotaryURL,
		maxResponseSize: defaultMaxResponseSize,
		client:          rs.client,
		rootRole:        root,
		snapshotRole:    snapshot,
		localRootTarget: previous,
		clock:           rs.clock,
	}
	targetFetcher, err := newNotaryTargetFetcher(settings)
	if err != nil {
		return nil, nil, errors.Wrap(err, "notary reader creation")
	}
	current, err := rs.notary.targets(targetFetcher)
	if err != nil {
		return nil, nil, errors.Wrap(err, "retrieving timestamp from notary")
	}
	changed := getChangedPaths(previous, current)
	return current, changed, nil
}

// Returns a list of any targets (paths) that have changed, or, are new.
func getChangedPaths(local *RootTarget, fromNotary *RootTarget) []string {
	var changed []string
	for targetName, fim := range fromNotary.paths {
		// check for new paths
		lfim, ok := local.paths[targetName]
		if !ok {
			changed = append(changed, targetName)
			continue
		}
		// if paths exist in both local and notary versions of the repo,
		// compare hashes to detect changes.
		if !fim.Equal(lfim) {
			changed = append(changed, targetName)
		}
	}
	return changed
}

func getKeys(r *Root, sigs []Signature) map[keyID]Key {
	result := make(map[keyID]Key)
	for _, sig := range sigs {
		k, ok := r.keys()[sig.KeyID]
		if ok {
			result[sig.KeyID] = k
		}
	}
	return result
}

// 5.2. Otherwise, download the target (up to the number of bytes specified in
// the targets metadata), and verify that its hashes match the targets
// metadata. (We download up to this number of bytes, because in some cases,
// the exact number is unknown. This may happen, for example, if an external
// program is used to compute the root hash of a tree of targets files, and
// this program does not provide the total size of all of these files.)
// If consistent snapshots are not used (see Section 7), then the filename
// used to download the target file is of the fixed form FILENAME.EXT (e.g.,
// foobar.tar.gz).
// Otherwise, the filename is of the form HASH.FILENAME.EXT (e.g.,
// c14aeb4ac9f4a8fc0d83d12482b9197452f6adf3eb710e3b1e2b79e8d14cb681.foobar.tar.gz),
// where HASH is one of the hashes of the targets file listed in the targets
// metadata file found earlier in step 4.
// In either case, the client MUST write the file to non-volatile storage as
// FILENAME.EXT.
func (rs *repoMan) downloadTarget(target string, destination io.Writer) error {
	if rs.targets == nil {
		return errors.New("no targets present, was Update called?")
	}
	fim, ok := rs.targets.paths[target]
	if !ok {
		return errors.Errorf("unknown target %q", target)
	}
	// we expect our mirrored distribution targets to be located
	// at https://mirror.com/gun/targetname
	mirrorURL, err := url.Parse(rs.settings.MirrorURL)
	if err != nil {
		return errors.Wrap(err, "parse mirror url for download")
	}
	mirrorURL.Path = path.Join(mirrorURL.Path, rs.settings.GUN, string(target))

	request, err := http.NewRequest(http.MethodGet, mirrorURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "creating target request")
	}
	// Dissallow caching because if we are making this call, we know that the target
	// has changed and we want to make sure we get the data from the mirror, not
	// from cache.
	request.Header.Add(cacheControl, cachePolicyNoStore)
	resp, err := rs.client.Do(request)
	if err != nil {
		return errors.Wrap(err, "fetching target from mirror")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("get target returned %q", resp.Status)
	}
	stream := io.LimitReader(resp.Body, fim.Length)
	if err := fim.verify(io.TeeReader(stream, destination)); err != nil {
		return errors.Wrap(err, "verifying current target download")
	}
	return nil
}

func verifySignatures(role marshaller, keys map[keyID]Key, sigs []Signature, threshold int) error {
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
