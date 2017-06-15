package tuf

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLValidation(t *testing.T) {
	r, err := newNotaryRepo("https://foo.com/zip.json", "kolide/agent/linux", true)
	require.Nil(t, err)
	assert.NotNil(t, r)
	assert.True(t, r.skipVerify)
	assert.NotNil(t, r.url)
	assert.Equal(t, "kolide/agent/linux", r.gun)

	r, err = newNotaryRepo("HtTps://foo.com/zip.json", "kolide/agent/linux", false)
	require.Nil(t, err)
	assert.NotNil(t, r)

	r, err = newNotaryRepo("http://foo.com/zip.json", "kolide/agent/linux", false)
	require.NotNil(t, err)
	assert.Nil(t, r)

	r, err = newNotaryRepo("garbage", "kolide/agent/linux", false)
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
