package tuf

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLValidation(t *testing.T) {
	settings := &Settings{
		NotaryURL: "https://foo.com/zip.json",
		GUN:       "kolide/agent/linux",
	}

	hclient := testHTTPClient()
	r, err := newNotaryRepo(settings, defaultMaxResponseSize, hclient)
	require.Nil(t, err)
	assert.NotNil(t, r)
	assert.NotNil(t, r.url)
	assert.Equal(t, "kolide/agent/linux", r.gun)
	settings.NotaryURL = "HtTps://foo.com/zip.json"
	r, err = newNotaryRepo(settings, defaultMaxResponseSize, hclient)
	require.Nil(t, err)
	assert.NotNil(t, r)
	settings.NotaryURL = "http://foo.com/zip.json"
	r, err = newNotaryRepo(settings, defaultMaxResponseSize, hclient)
	require.NotNil(t, err)
	assert.Nil(t, r)
	settings.NotaryURL = "garbage"
	r, err = newNotaryRepo(settings, defaultMaxResponseSize, hclient)
	require.NotNil(t, err)
	assert.Nil(t, r)
}

func TestPathValidation(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "test")
	require.Nil(t, err)
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()
	// path must be a directory or symlink, not a regular file
	r, err := newLocalRepo(tempFile.Name())
	assert.NotNil(t, err)
	assert.Nil(t, r)
	expected := path.Dir(tempFile.Name())
	r, err = newLocalRepo(expected)
	require.Nil(t, err)
	require.NotNil(t, r)
	assert.Equal(t, expected, r.repoPath)
}

func createLocalRepo(version int, location string, t *testing.T) {
	roles := []string{"root", "timestamp", "snapshot", "targets"}
	for _, role := range roles {
		source := fmt.Sprintf("testdata/kolide/agent/linux/%s.%d.json", role, version)
		buff := testAsset(t, source)
		func() {
			target := filepath.Join(location, fmt.Sprintf("%s.json", role))
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
			require.Nil(t, err)
			defer f.Close()
			_, err = io.Copy(f, bytes.NewBuffer(buff))
			require.Nil(t, err)
		}()
	}
}

// returns local repo path and staging path
func setupTufLocal(version int, t *testing.T) (string, string) {
	localRepoPath, err := ioutil.TempDir("", "repo")
	require.Nil(t, err)
	stagingPath, err := ioutil.TempDir("", "staging")
	require.Nil(t, err)
	createLocalRepo(version, localRepoPath, t)
	return localRepoPath, stagingPath
}

type mockHandler struct {
	matcher *regexp.Regexp
	handler func(w http.ResponseWriter, r *http.Request)
}

// Returns a mock notary server, and a mock mirror
// The notfoundversion should be set to one greater than the version of the root
// file we are using.
func setupTufRemote(version int, notfoundVersion string, t *testing.T) (*httptest.Server, *httptest.Server) {
	roleHandlers := []mockHandler{
		mockHandler{
			matcher: regexp.MustCompile(`root\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {

				if regexp.MustCompile(notfoundVersion + `\.root\.json$`).MatchString(r.RequestURI) {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				source := fmt.Sprintf("testdata/kolide/agent/linux/root.%d.json", version)
				buff := testAsset(t, source)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`timestamp\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("testdata/kolide/agent/linux/timestamp.%d.json", version)
				buff := testAsset(t, source)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`snapshot\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("testdata/kolide/agent/linux/snapshot.%d.json", version)
				buff := testAsset(t, source)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`targets\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("testdata/kolide/agent/linux/targets.%d.json", version)
				buff := testAsset(t, source)
				w.Write(buff)
			},
		},
	}

	notary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, mock := range roleHandlers {
			if mock.matcher.MatchString(r.RequestURI) {
				mock.handler(w, r)
			}
		}
	}))
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/kolide/agent/linux/somedir/target.0":
			buff := testAsset(t, fmt.Sprintf("testdata/kolide/agent/linux/target.0.%d", version))
			w.Write(buff)
		case "/kolide/agent/linux/somedir/target.1":
			buff := testAsset(t, fmt.Sprintf("testdata/kolide/agent/linux/target.1.%d", version))
			w.Write(buff)
		default:
			require.FailNow(t, "invalid uri", r.RequestURI)
		}
	}))

	return notary, mirror
}

// these tests work on versioned role files and targets that we create interactively
// using notary and then save them in bin data so we can mimic key rotations,
// updating distributables etc.
func TestClientNoUpdates(t *testing.T) {
	localRepoPath, stagingPath := setupTufLocal(0, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(0, "2", t)
	defer notary.Close()
	defer mirror.Close()
	settings := testSettings(localRepoPath, notary, mirror)
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")
	mockClock := clock.NewMockClock(testTime)
	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()), withClock(mockClock))
	require.Nil(t, err)
	fims, latest, err := client.Update()
	require.Nil(t, err)
	require.True(t, latest)
	assert.Len(t, fims, 2)

}

func testSettings(localRepo string, notary, mirror *httptest.Server) *Settings {
	settings := Settings{
		LocalRepoPath: localRepo,
		MirrorURL:     mirror.URL,
		NotaryURL:     notary.URL,
		GUN:           "kolide/agent/linux",
	}
	return &settings
}

func testHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func TestClientWithUpdates(t *testing.T) {
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")
	localRepoPath, stagingPath := setupTufLocal(0, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(1, "2", t)
	defer notary.Close()
	defer mirror.Close()

	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()), withClock(clock.NewMockClock(testTime)))
	require.Nil(t, err)

	_, latest, err := client.Update()
	require.Nil(t, err)
	require.False(t, latest)

	// make sure all the files we are supposed to create are there
	files := []string{
		filepath.Join(localRepoPath, "root.json"),
		filepath.Join(localRepoPath, "timestamp.json"),
		filepath.Join(localRepoPath, "snapshot.json"),
		filepath.Join(localRepoPath, "targets.json"),
	}

	for _, f := range files {
		fs, err := os.Stat(f)
		require.False(t, os.IsNotExist(err))
		require.NotNil(t, fs)
	}
}

func TestWithRootKeyRotation(t *testing.T) {
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")
	localRepoPath, stagingPath := setupTufLocal(1, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(2, "3", t)
	defer notary.Close()
	defer mirror.Close()
	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()), withClock(clock.NewMockClock(testTime)))
	require.Nil(t, err)

	_, latest, err := client.Update()
	require.Nil(t, err)
	require.True(t, latest)

	// make sure all the files we are supposed to create are there
	files := []string{
		filepath.Join(localRepoPath, "root.json"),
		filepath.Join(localRepoPath, "timestamp.json"),
		filepath.Join(localRepoPath, "snapshot.json"),
		filepath.Join(localRepoPath, "targets.json"),
	}

	for _, f := range files {
		fs, err := os.Stat(f)
		require.False(t, os.IsNotExist(err))
		require.NotNil(t, fs)
	}
}

func TestWithTimestampKeyRotation(t *testing.T) {
	testTime, _ := time.Parse(time.UnixDate, "Sat Jul 1 18:00:00 CST 2017")
	localRepoPath, stagingPath := setupTufLocal(3, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(4, "3", t)
	defer notary.Close()
	defer mirror.Close()
	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()), withClock(clock.NewMockClock(testTime)))
	require.Nil(t, err)

	_, latest, err := client.Update()
	require.Nil(t, err)
	require.True(t, latest)

	// make sure all the files we are supposed to create are there
	files := []string{
		filepath.Join(localRepoPath, "root.json"),
		filepath.Join(localRepoPath, "timestamp.json"),
		filepath.Join(localRepoPath, "snapshot.json"),
		filepath.Join(localRepoPath, "targets.json"),
	}

	for _, f := range files {
		fs, err := os.Stat(f)
		require.False(t, os.IsNotExist(err))
		require.NotNil(t, fs)
	}
}
