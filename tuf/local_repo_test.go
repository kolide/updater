package tuf

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupLocalTests(t *testing.T) string {
	baseDir, err := ioutil.TempDir("", "test")
	require.Nil(t, err)
	roles := []role{roleRoot, roleTargets, roleSnapshot, roleTimestamp}
	for _, r := range roles {
		func() {
			buff := testAsset(t, fmt.Sprintf("testdata/data/%s.json", r))
			f, err := os.OpenFile(filepath.Join(baseDir, fmt.Sprintf("%s.json", r)), os.O_CREATE|os.O_WRONLY, 0644)
			require.Nil(t, err)
			defer f.Close()
			_, err = io.Copy(f, bytes.NewBuffer(buff))
			require.Nil(t, err)
		}()
	}
	return baseDir
}

func TestGetLocalRoles(t *testing.T) {
	baseDir := setupLocalTests(t)
	defer os.RemoveAll(baseDir)

	l, err := newLocalRepo(baseDir)
	require.Nil(t, err)
	root, err := l.root()
	require.Nil(t, err)
	require.NotNil(t, root)
	assert.Equal(t, "2027-06-10T13:25:45.170347322-05:00", root.Signed.Expires.Format(time.RFC3339Nano))

	ts, err := l.timestamp()
	require.Nil(t, err)
	require.NotNil(t, ts)
	assert.Equal(t, "2017-06-26T19:32:36.967988706Z", ts.Signed.Expires.Format(time.RFC3339Nano))

	ss, err := l.snapshot()
	require.Nil(t, err)
	require.NotNil(t, ss)
	assert.Equal(t, "2020-06-11T14:32:32.161365749-05:00", ss.Signed.Expires.Format(time.RFC3339Nano))

}

func TestGetLocalTargets(t *testing.T) {
	l := localRepo{}
	trg, err := l.targets(&mockLocalRepoReader{"testdata/delegation/0/"})
	require.Nil(t, err)
	require.NotNil(t, trg)
	assert.Equal(t, "2020-06-27T14:16:29.4823129-05:00", trg.Signed.Expires.Format(time.RFC3339Nano))
}
