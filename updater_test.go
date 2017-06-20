package updater

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/kolide/updater/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	fakeDir, _ := os.Getwd()
	settings := tuf.Settings{
		GUN:               "kolide/agent/linux",
		LocalRepoPath:     fakeDir,
		InstallDir:        fakeDir,
		StagingPath:       fakeDir,
		MirrorURL:         "https://mirror.com",
		RemoteRepoBaseURL: "https://notary.com",
	}
	u, err := New(settings, exec.Cmd{})
	require.Nil(t, err)
	assert.Equal(t, defaultCheckFrequency, u.checkFrequency)

	u, err = New(settings, exec.Cmd{}, Frequency(9*time.Minute))
	assert.Equal(t, ErrCheckFrequency, err)
	assert.Nil(t, u)

	u, err = New(settings,
		exec.Cmd{},
		Frequency(601*time.Second),
		WantNotifications(func(evt Events) {}),
	)
	assert.Nil(t, err)
	require.NotNil(t, u)
	assert.NotNil(t, u.notificationHandler)
}

func TestBackupAndRestore(t *testing.T) {
	installDir, err := ioutil.TempDir("", "install")
	require.Nil(t, err)
	defer os.RemoveAll(installDir)
	installSubdirs := path.Join(installDir, "sub1", "sub2")
	err = os.MkdirAll(installSubdirs, 0744)
	require.Nil(t, err)
	stagingDir, err := ioutil.TempDir("", "staging")
	require.Nil(t, err)
	defer os.RemoveAll(stagingDir)
	fileName := path.Join(installDir, "foo")
	err = ioutil.WriteFile(fileName, []byte("some data"), 0644)
	require.Nil(t, err)
	subFileName := path.Join(installSubdirs, "bar")
	err = ioutil.WriteFile(subFileName, []byte("other stuff"), 0644)
	require.Nil(t, err)
	backupDir, err := backup(installDir, stagingDir)
	require.Nil(t, err)
	require.NotEmpty(t, backupDir)
	_, err = os.Stat(path.Join(backupDir, "foo"))
	require.Nil(t, err)
	_, err = os.Stat(path.Join(backupDir, "sub1", "sub2", "bar"))
	require.Nil(t, err)

	// let's mock in install by putting something additional in the install dir
	newInstallFile := path.Join(installDir, "baz")
	err = ioutil.WriteFile(newInstallFile, []byte("other things"), 0644)
	require.Nil(t, err)
	// now you see it
	_, err = os.Stat(newInstallFile)
	require.Nil(t, err)
	err = rollback(backupDir, installDir)
	require.Nil(t, err)
	// now you don't
	_, err = os.Stat(newInstallFile)
	require.NotNil(t, err)
	require.True(t, os.IsNotExist(err))
	// but old install files are still around
	_, err = os.Stat(fileName)
	require.Nil(t, err)
	_, err = os.Stat(subFileName)
	require.Nil(t, err)
}
