package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLocalRepoReader struct {
	rootDir string
}

func (lr *mockLocalRepoReader) fetch(role string) (*Targets, error) {
	buff, err := test.Asset(lr.rootDir + role + ".json")
	if err != nil {
		return nil, err
	}
	var targ Targets
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targ)
	if err != nil {
		return nil, err
	}
	return &targ, err
}

func TestMockReader(t *testing.T) {
	rdr := mockLocalRepoReader{"test/delegation/0/"}
	tt := []struct {
		path          string
		expectSuccess bool
	}{
		{"targets", true},
		{"targets/bar", true},
		{"targets/role/foo", true},
		{"targets/zip/foo", false},
	}
	for _, tc := range tt {
		t.Run(tc.path, func(t *testing.T) {
			targ, err := rdr.fetch(tc.path)
			if tc.expectSuccess {
				assert.Nil(t, err)
				assert.NotNil(t, targ)
			} else {
				assert.NotNil(t, err)
				assert.Nil(t, targ)
			}
		})
	}
}

func TestPopulateLocalTargetsWithChildren(t *testing.T) {
	rdr := mockLocalRepoReader{"test/delegation/0/"}
	root, err := targetTreeBuilder(&rdr)
	require.Nil(t, err)
	require.NotNil(t, root)
	assert.Len(t, root.targetPrecedence, 4)
	tt := []struct {
		role               string
		expectedPrecedence int
	}{
		{"targets", 0},
		{"targets/role", 1},
		{"targets/role/foo", 2},
		{"targets/bar", 3},
	}
	for _, tc := range tt {
		t.Run("precedence "+tc.role, func(t *testing.T) {
			targ, ok := root.targetLookup[tc.role]
			require.True(t, ok)
			assert.Equal(t, targ, root.targetPrecedence[tc.expectedPrecedence])
		})
	}
}

func setupValidationTest(t *testing.T, testRoot string) (*Root, *Snapshot, *RootTarget) {
	rdr := mockLocalRepoReader{testRoot + "/"}
	rootTarget, err := targetTreeBuilder(&rdr)
	require.Nil(t, err)
	var ss Snapshot
	buff, err := test.Asset(path.Join(testRoot, string(roleSnapshot)+".json"))
	require.Nil(t, err)
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&ss)
	require.Nil(t, err)
	var root Root
	buff, err = test.Asset(path.Join(testRoot, string(roleRoot)+".json"))
	require.Nil(t, err)
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.Nil(t, err)
	return &root, &ss, rootTarget
}

func TestTargetReadWithValidations(t *testing.T) {
	testRootPath := "test/delegation/0"
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testDataPath := strings.Replace(strings.Replace(r.RequestURI, "/v2/", "", 1), "/_trust/tuf", "", 1)
		buff, err := test.Asset(testDataPath)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(buff)
	}))
	defer svr.Close()
	rootRole, snapshotRole, rootTarget := setupValidationTest(t, testRootPath)
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")

	rrs := notaryTargetFetcherSettings{
		gun:             testRootPath,
		client:          testHTTPClient(),
		url:             svr.URL,
		maxResponseSize: defaultMaxResponseSize,
		rootRole:        rootRole,
		snapshotRole:    snapshotRole,
		localRootTarget: rootTarget,
		clock:           clock.NewMockClock(testTime),
	}
	rtr, err := newNotaryTargetFetcher(&rrs)
	require.Nil(t, err)
	require.NotNil(t, rtr)
	var notary notaryRepo
	remoteRootTarget, err := notary.targets(rtr)
	require.Nil(t, err)
	require.NotNil(t, remoteRootTarget)
}

func noChangeDetected(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.Nil(t, err)
	_, latest, err := client.Update()
	require.Nil(t, err)
	assert.True(t, latest)
}

func existingPathChanged(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.Nil(t, err)
	fims, latest, err := client.Update()
	require.Nil(t, err)
	require.Nil(t, err)
	assert.False(t, latest)
	_, ok := fims["edge/target"]
	require.True(t, ok)
	download := filepath.Join(stageDir, "target")
	out, err := os.Create(download)
	require.Nil(t, err)
	defer out.Close()
	err = client.Download("edge/target", out)
	require.Nil(t, err)
	out.Close()
	fi, err := os.Stat(download)
	require.Nil(t, err)
	fim, ok := client.manager.targets.paths["edge/target"]
	require.True(t, ok)
	assert.Equal(t, fi.Size(), fim.Length)
}

// A delegate with lower precedence adds file, because a higher precedence delegate 'owns' path change should not
// trigger change
func nonprecedentPathChange(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.Nil(t, err)
	_, latest, err := client.Update()
	require.Nil(t, err)
	// Path changed, but not by the highest precedence delegate, so we have the
	// latest.
	require.True(t, latest)
	download := filepath.Join(stageDir, "target")
	out, err := os.Create(download)
	require.Nil(t, err)
	defer out.Close()
	err = client.Download("latest/target", out)
	// lower precedence role uploaded to mirror, but should cause error
	require.NotNil(t, err)
	out.Close()
}

func autoupdateDetectedChange(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	var (
		called    bool
		path      string
		updateErr error
		lock      sync.Mutex
	)
	onUpdate := func(stagingPath string, err error) {
		lock.Lock()
		defer lock.Unlock()
		called = true
		path = stagingPath
		updateErr = err
	}
	client, err := NewClient(
		settings, WithHTTPClient(c),
		withClock(k),
		WithAutoUpdate("edge/target", stageDir, onUpdate),
	)
	require.Nil(t, err)
	// we have to wait to few moments for the delegate to get called
	time.Sleep(200 * time.Millisecond)
	defer client.Stop()
	lock.Lock()
	defer lock.Unlock()
	require.True(t, called)
	assert.Regexp(t, regexp.MustCompile("/edge/target$"), path)
	assert.Nil(t, updateErr)
	_, err = os.Stat(path)
	assert.Nil(t, err)
}

func wontCrashOnNilAutoupdate(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	_, err := NewClient(
		settings, WithHTTPClient(c),
		withClock(k),
		WithAutoUpdate("edge/target", stageDir, nil),
	)
	assert.NotNil(t, err)
}

const (
	assetRoot  = "test/delegation"
	mirrorRoot = "test/mirror"
	testGUN    = "kolide/launcher/darwin"
)

func createLocalTestRepo(t *testing.T, localRepoDir, assetParentDir string) {
	paths, err := test.AssetDir(assetParentDir)
	require.Nil(t, err)
	for _, unprocessed := range paths {
		if regexp.MustCompile("\\.json$").MatchString(unprocessed) {
			func() {
				buff, err := test.Asset(path.Join(assetParentDir, unprocessed))
				require.Nil(t, err)
				out, err := os.Create(filepath.Join(localRepoDir, unprocessed))
				require.Nil(t, err)
				defer out.Close()
				_, err = io.Copy(out, bytes.NewBuffer(buff))
				require.Nil(t, err)
			}()
		} else {
			// this is a directory create it and recurse into it
			local := filepath.Join(localRepoDir, unprocessed)
			asset := path.Join(assetParentDir, unprocessed)
			err = os.MkdirAll(local, 0755)
			require.Nil(t, err)
			createLocalTestRepo(t, local, asset)
		}
	}
}

func setupEndToEndTest(t *testing.T, remoteVersion, localVersion int) (*Settings, string, func()) {
	stagingDir, err := ioutil.TempDir("", "staging")
	require.Nil(t, err)
	localRepoDir, err := ioutil.TempDir("", "local")
	require.Nil(t, err)
	createLocalTestRepo(t, localRepoDir, path.Join(assetRoot, strconv.Itoa(localVersion)))
	notary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/_notary_server/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		base := strings.Replace(r.RequestURI, fmt.Sprintf("/v2/%s/_trust/tuf/", testGUN), "", 1)
		buff, err := test.Asset(path.Join(assetRoot, strconv.Itoa(remoteVersion), base))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, err = w.Write(buff)
		require.Nil(t, err)
	}))
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := strings.Replace(r.RequestURI, "/"+testGUN, "", 1)
		assetPath := path.Join(fmt.Sprintf("%s/%d", mirrorRoot, remoteVersion), base)
		buff, err := test.Asset(assetPath)
		require.Nil(t, err)
		w.Write(buff)
	}))
	settings := &Settings{
		LocalRepoPath: localRepoDir,
		NotaryURL:     notary.URL,
		MirrorURL:     mirror.URL,
		GUN:           testGUN,
	}
	cleanup := func() {
		os.RemoveAll(stagingDir)
		os.RemoveAll(localRepoDir)
		notary.Close()
		mirror.Close()
	}
	return settings, stagingDir, cleanup
}

func TestEndToEnd(t *testing.T) {
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")
	mockClock := clock.NewMockClock(testTime)
	client := testHTTPClient()

	tt := []struct {
		name              string
		localRepoVersion  int
		remoteRepoVersion int
		testCase          func(t *testing.T, settings *Settings, client *http.Client, stageDir string, c *clock.MockClock)
	}{
		{"no change detected", 0, 1, noChangeDetected},
		{"existing path changed", 1, 2, existingPathChanged},
		{"autoupdate with change", 1, 2, autoupdateDetectedChange},
		{"lower precedent change", 2, 3, nonprecedentPathChange},
		{"nil autoupdate func", 1, 2, wontCrashOnNilAutoupdate},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			settings, stagingDir, cleanup := setupEndToEndTest(t, tc.remoteRepoVersion, tc.localRepoVersion)
			defer cleanup()
			tc.testCase(t, settings, client, stagingDir, mockClock)
		})
	}
}
