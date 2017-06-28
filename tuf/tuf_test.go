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

	"github.com/kolide/updater/test"
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
		source := fmt.Sprintf("test/kolide/agent/linux/%s.%d.json", role, version)
		buff, err := test.Asset(source)
		require.Nil(t, err)
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
				source := fmt.Sprintf("test/kolide/agent/linux/root.%d.json", version)
				buff, err := test.Asset(source)
				require.Nil(t, err)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`timestamp\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("test/kolide/agent/linux/timestamp.%d.json", version)
				buff, err := test.Asset(source)
				require.Nil(t, err)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`snapshot\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("test/kolide/agent/linux/snapshot.%d.json", version)
				buff, err := test.Asset(source)
				require.Nil(t, err)
				w.Write(buff)
			},
		},
		mockHandler{
			matcher: regexp.MustCompile(`targets\.json$`),
			handler: func(w http.ResponseWriter, r *http.Request) {
				source := fmt.Sprintf("test/kolide/agent/linux/targets.%d.json", version)
				buff, err := test.Asset(source)
				require.Nil(t, err)
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
			buff, err := test.Asset(fmt.Sprintf("test/kolide/agent/linux/target.0.%d", version))
			require.Nil(t, err)
			w.Write(buff)
		case "/kolide/agent/linux/somedir/target.1":
			buff, err := test.Asset(fmt.Sprintf("test/kolide/agent/linux/target.1.%d", version))
			require.Nil(t, err)
			w.Write(buff)
		default:
			require.FailNow(t, "invalid uri", r.RequestURI)
		}
	}))

	return notary, mirror
}

func TestBackupAndRecover(t *testing.T) {
	localRepoPath, stagingPath := setupTufLocal(0, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)

	rm := repoMan{
		settings: &Settings{
			LocalRepoPath: localRepoPath,
		},
	}
	tag := time.Now().Format(time.Now().Format(filetimeFormat))
	err := rm.backupRoles(tag)
	require.Nil(t, err)

	// remove files and make sure that they get restored
	backupFiles := []string{
		filepath.Join(localRepoPath, fmt.Sprintf("root.%s.json", tag)),
		filepath.Join(localRepoPath, fmt.Sprintf("timestamp.%s.json", tag)),
		filepath.Join(localRepoPath, fmt.Sprintf("snapshot.%s.json", tag)),
		filepath.Join(localRepoPath, fmt.Sprintf("targets.%s.json", tag)),
	}
	files := []string{
		filepath.Join(localRepoPath, "root.json"),
		filepath.Join(localRepoPath, "timestamp.json"),
		filepath.Join(localRepoPath, "snapshot.json"),
		filepath.Join(localRepoPath, "targets.json"),
	}
	// backup file should exist, regular file should not
	for i := range files {
		_, err = os.Stat(files[i])
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(backupFiles[i])
		assert.Nil(t, err)
	}

	err = rm.restoreRoles(tag)
	assert.Nil(t, err)
	// regular file should exist, backup should not
	for i := range files {
		_, err = os.Stat(files[i])
		assert.Nil(t, err)
		_, err = os.Stat(backupFiles[i])
		assert.True(t, os.IsNotExist(err))
	}

	// do a save that we know will blow up
	err = rm.save(tag)
	require.NotNil(t, err)

	// should have original files, no backup files
	for i := range files {
		_, err = os.Stat(files[i])
		assert.Nil(t, err)
		_, err = os.Stat(backupFiles[i])
		assert.True(t, os.IsNotExist(err))
	}

	// now do a save that should work
	repo, err := newLocalRepo(localRepoPath)
	require.Nil(t, err)
	rm.root, err = repo.root()
	require.Nil(t, err)
	rm.timestamp, err = repo.timestamp()
	require.Nil(t, err)
	rm.targets, err = repo.targets()
	require.Nil(t, err)
	rm.snapshot, err = repo.snapshot()
	require.Nil(t, err)

	err = rm.save(tag)
	require.Nil(t, err)

	// should have original files
	for i := range files {
		_, err = os.Stat(files[i])
		assert.Nil(t, err)
	}
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

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()))
	require.Nil(t, err)

	_, latest, err := client.Update()
	require.Nil(t, err)
	require.True(t, latest)
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
	localRepoPath, stagingPath := setupTufLocal(0, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(1, "2", t)
	defer notary.Close()
	defer mirror.Close()

	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()))
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
	localRepoPath, stagingPath := setupTufLocal(1, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(2, "3", t)
	defer notary.Close()
	defer mirror.Close()
	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()))
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
	localRepoPath, stagingPath := setupTufLocal(3, t)
	defer os.RemoveAll(localRepoPath)
	defer os.RemoveAll(stagingPath)
	notary, mirror := setupTufRemote(4, "3", t)
	defer notary.Close()
	defer mirror.Close()
	settings := testSettings(localRepoPath, notary, mirror)

	client, err := NewClient(settings, WithHTTPClient(testHTTPClient()))
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
