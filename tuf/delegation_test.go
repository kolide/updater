package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAsset(t *testing.T, path string) []byte {
	data, err := ioutil.ReadFile(path)
	require.NoError(t, err, path)
	return data
}

type mockLocalRepoReader struct {
	rootDir string
}

func (lr *mockLocalRepoReader) fetch(role string) (*Targets, error) {
	buff, err := ioutil.ReadFile(lr.rootDir + role + ".json")
	if err != nil {
		return nil, errors.Wrap(err, "fetch role")
	}

	var targ Targets
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targ)
	if err != nil {
		return nil, err
	}
	return &targ, err
}

func TestMockReader(t *testing.T) {
	t.Parallel()

	rdr := mockLocalRepoReader{"testdata/delegation/0/"}
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
	t.Parallel()

	rdr := mockLocalRepoReader{"testdata/delegation/0/"}
	root, err := targetTreeBuilder(&rdr)
	require.NoError(t, err)
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
	require.NoError(t, err)
	var ss Snapshot
	buff := testAsset(t, path.Join(testRoot, string(roleSnapshot)+".json"))
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&ss)
	require.NoError(t, err)
	var root Root
	buff = testAsset(t, path.Join(testRoot, string(roleRoot)+".json"))
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.NoError(t, err)
	return &root, &ss, rootTarget
}

func TestTargetReadWithValidations(t *testing.T) {
	t.Parallel()

	testRootPath := "testdata/delegation/0"
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testDataPath := strings.Replace(strings.Replace(r.RequestURI, "/v2/", "", 1), "/_trust/tuf", "", 1)
		buff := testAsset(t, testDataPath)
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
	require.NoError(t, err)
	require.NotNil(t, rtr)
	var notary notaryRepo
	remoteRootTarget, err := notary.targets(rtr)
	require.NoError(t, err)
	require.NotNil(t, remoteRootTarget)
}

func noChangeDetected(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.NoError(t, err)
	_, latest, err := client.Update()
	require.NoError(t, err)
	assert.True(t, latest)
}

func existingPathChanged(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.NoError(t, err)
	fims, latest, err := client.Update()
	require.NoError(t, err)
	require.NoError(t, err)
	assert.False(t, latest)
	_, ok := fims["edge/target"]
	require.True(t, ok)
	download := filepath.Join(stageDir, "target")
	out, err := os.Create(download)
	require.NoError(t, err)
	defer out.Close()
	err = client.Download("edge/target", out)
	require.NoError(t, err)
	out.Close()
	fi, err := os.Stat(download)
	require.NoError(t, err)
	fims, err = client.getFIMMap()
	require.NoError(t, err)
	fim, ok := fims["edge/target"]
	require.True(t, ok)
	assert.Equal(t, fi.Size(), fim.Length)
}

// A delegate with lower precedence adds file, because a higher precedence delegate 'owns' path change should not
// trigger change
func nonprecedentPathChange(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	client, err := NewClient(settings, WithHTTPClient(c), withClock(k))
	require.NoError(t, err)
	_, latest, err := client.Update()
	require.NoError(t, err)
	// Path changed, but not by the highest precedence delegate, so we have the
	// latest.
	require.True(t, latest)
	download := filepath.Join(stageDir, "target")
	out, err := os.Create(download)
	require.NoError(t, err)
	defer out.Close()
	err = client.Download("latest/target", out)
	// lower precedence role uploaded to mirror, but should cause error
	require.NotNil(t, err)
	out.Close()
}

func autoupdateDetectedChange(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	var (
		path  string
		cberr error
	)

	onUpdate := func(stagingPath string, err error) {
		path = stagingPath
		cberr = err
	}

	client, err := NewClient(
		settings, WithHTTPClient(c),
		withClock(k),
		WithAutoUpdate("edge/target", stageDir, onUpdate),
	)
	require.NoError(t, err)
	client.Stop()

	// there should be no problems with concurrent access here because both
	// goroutines should be shut down
	assert.Regexp(t, regexp.MustCompile("/edge/target$"), path)
	assert.Nil(t, cberr)
	_, err = os.Stat(path)
	assert.Nil(t, err)
}

func autoupdateDetectedChangeAfterInterval(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	var (
		path   string
		cbErr  error
		called bool
	)

	onUpdate := func(stagingPath string, e error) {
		called = true
		path = stagingPath
		cbErr = e
	}

	client, err := NewClient(
		settings, WithHTTPClient(c),
		withClock(k),
		loadOnStart(false),
		WithAutoUpdate("edge/target", stageDir, onUpdate),
	)
	require.NoError(t, err)
	client.Stop()
	// verify that it didn't run
	assert.False(t, called)

	client, err = NewClient(
		settings, WithHTTPClient(c),
		withClock(k),
		loadOnStart(false),
		WithAutoUpdate("edge/target", stageDir, onUpdate),
	)
	require.NoError(t, err)
	// advance clock
	k.AddTime(defaultCheckFrequency + time.Second)
	// we need to pause to let delegate finish
	time.Sleep(10 * time.Millisecond)
	client.Stop()
	require.True(t, called)
	//The callback was invoked and proper file was downloaded
	assert.Regexp(t, regexp.MustCompile("/edge/target$"), path)
	assert.Nil(t, cbErr)
	_, err = os.Stat(path)
	assert.Nil(t, err)
}

// Test that auto update and explicit update/download calls can occur simultaneously and also give the race
// detector something to chew on.
func interleavedOperations(t *testing.T, settings *Settings, c *http.Client, stageDir string, k *clock.MockClock) {
	gen := rand.New(rand.NewSource(time.Now().UnixNano()))
	onUpdate := func(gen *rand.Rand) func(stagingPath string, e error) {
		wait := gen.Int() % 1000
		return func(s string, e error) {
			time.Sleep(time.Duration(wait) * time.Microsecond)
		}
	}

	for i := 0; i < 20; i++ {
		client, err := NewClient(
			settings, WithHTTPClient(c),
			withClock(k),
			WithFrequency(time.Duration((gen.Int()%500))*time.Microsecond),
			WithAutoUpdate("edge/target", stageDir, onUpdate(gen)),
		)
		require.NoError(t, err)
		_, _, err = client.Update()
		require.NoError(t, err)
		wr, err := ioutil.TempFile("", "")
		require.NoError(t, err)
		err = client.Download("edge/target", wr)
		os.Remove(wr.Name())
		assert.Nil(t, err)
		client.Stop()
	}
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
	assetRoot  = "testdata/delegation"
	mirrorRoot = "testdata/mirror"
	testGUN    = "kolide/launcher/darwin"
)

func createLocalTestRepo(t *testing.T, localRepoDir, assetParentDir string) {
	paths, err := ioutil.ReadDir(assetParentDir)
	require.NoError(t, err)
	for _, u := range paths {
		unprocessed := u.Name()
		if regexp.MustCompile("\\.json$").MatchString(unprocessed) {
			func() {
				buff := testAsset(t, path.Join(assetParentDir, unprocessed))
				out, err := os.Create(filepath.Join(localRepoDir, unprocessed))
				require.NoError(t, err)
				defer out.Close()
				_, err = io.Copy(out, bytes.NewBuffer(buff))
				require.NoError(t, err)
			}()
		} else {
			// this is a directory create it and recurse into it
			local := filepath.Join(localRepoDir, unprocessed)
			asset := path.Join(assetParentDir, unprocessed)
			err = os.MkdirAll(local, 0755)
			require.NoError(t, err)
			createLocalTestRepo(t, local, asset)
		}
	}
}

func setupEndToEndTest(t *testing.T, remoteVersion, localVersion int) (*Settings, string, func()) {
	stagingDir, err := ioutil.TempDir("", "staging")
	require.NoError(t, err)
	localRepoDir, err := ioutil.TempDir("", "local")
	require.NoError(t, err)
	createLocalTestRepo(t, localRepoDir, path.Join(assetRoot, strconv.Itoa(localVersion)))
	notary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/_notary_server/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		base := strings.Replace(r.RequestURI, fmt.Sprintf("/v2/%s/_trust/tuf/", testGUN), "", 1)
		buff, err := ioutil.ReadFile(path.Join(assetRoot, strconv.Itoa(remoteVersion), base))
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			require.NoError(t, err)
		}
		_, err = w.Write(buff)
		require.NoError(t, err)
	}))
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := strings.Replace(r.RequestURI, "/"+testGUN, "", 1)
		assetPath := path.Join(fmt.Sprintf("%s/%d", mirrorRoot, remoteVersion), base)
		buff := testAsset(t, assetPath)
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
	t.Parallel()

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
		{"autoupdate interval works", 1, 2, autoupdateDetectedChangeAfterInterval},
		{"interleaved operations", 1, 2, interleavedOperations},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			settings, stagingDir, cleanup := setupEndToEndTest(t, tc.remoteRepoVersion, tc.localRepoVersion)
			defer cleanup()
			tc.testCase(t, settings, client, stagingDir, mockClock)
		})
	}
}
