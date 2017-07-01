package tuf

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/y0ssar1an/q"
)

func TestCheckForDirectoryPresence(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	require.Nil(t, err)
	defer os.RemoveAll(dir)
	// directory present
	err = checkForDirectoryPresence(dir)
	assert.Nil(t, err)
	err = os.RemoveAll(dir)
	require.Nil(t, err)
	// directory missing
	err = checkForDirectoryPresence(dir)
	assert.NotNil(t, err)
	// path present but not a directory
	f, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(f.Name())
	err = checkForDirectoryPresence(f.Name())
	assert.NotNil(t, err)
}

func createMockRepo(sources []string) (string, []string, error) {
	tufDir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", nil, err
	}
	locations := make([]string, 0)
	for _, source := range sources {
		fileName := filepath.Base(source)
		stripped := strings.Replace(source, "test/delegation/0/", "", 1)
		pathPart := filepath.Dir(stripped)
		target := filepath.Join(tufDir, pathPart, fileName)
		locations = append(locations, target)
		buff, err := test.Asset(source)
		if err != nil {
			return "", nil, err
		}
		pathPart = filepath.Dir(target)
		if err = checkForDirectoryPresence(pathPart); err != nil {
			if err = os.MkdirAll(pathPart, 0755); err != nil {
				return "", nil, err
			}
		}
		err = func() error {
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(f, bytes.NewBuffer(buff))
			return err
		}()
		if err != nil {
			return "", nil, err
		}
	}
	q.Q(tufDir)
	return tufDir, locations, nil
}

var testFilePaths = []string{
	"test/delegation/0/root.json",
	"test/delegation/0/snapshot.json",
	"test/delegation/0/targets/bar.json",
	"test/delegation/0/targets/role/foo.json",
	"test/delegation/0/targets/role.json",
	"test/delegation/0/targets.json",
	"test/delegation/0/timestamp.json",
}

func TestBackupAndRecovery(t *testing.T) {
	olderBackupTag := time.Now().UTC().Add(-61 * time.Minute).Format(backupFileTimeTagFormat)
	newerBackupTag := time.Now().UTC().Add(-59 * time.Minute).Format(backupFileTimeTagFormat)

	repoDir, repoFileNames, err := createMockRepo(testFilePaths)
	require.Nil(t, err)
	defer os.RemoveAll(repoDir)
	// It should move repo files to backup
	err = backupTUFRepo(repoDir, olderBackupTag)
	assert.Nil(t, err)

	err = backupTUFRepo(repoDir, newerBackupTag)
	assert.Nil(t, err)

	for _, name := range repoFileNames {
		backupFile := strings.Replace(name, ".json", fmt.Sprintf(".%s.json", olderBackupTag), 1)
		t.Run("existence of "+filepath.Base(backupFile), func(t *testing.T) {
			_, err = os.Stat(backupFile)
			assert.Nil(t, err)
			// original file should still be present
			_, err = os.Stat(name)
			assert.Nil(t, err)
		})
		// remove original after backup
		require.Nil(t, os.Remove(name), "removing repo file")
	}
	// It should restore original repo files (which were removed)
	err = restoreTUFRepo(repoDir, olderBackupTag)
	assert.Nil(t, err)

	for _, name := range repoFileNames {
		t.Run("recovered "+filepath.Base(name), func(t *testing.T) {
			_, err = os.Stat(name)
			assert.Nil(t, err)
			backupFile := strings.Replace(name, ".json", fmt.Sprintf(".%s.json", olderBackupTag), 1)
			_, err = os.Stat(backupFile)
			assert.Nil(t, err)
		})
	}
	// It should remove the old backups, leave the newer ones
	err = removeAgedBackups(repoDir, 60*time.Minute)

	for _, name := range repoFileNames {
		oldBackup := strings.Replace(name, ".json", fmt.Sprintf(".%s.json", olderBackupTag), 1)
		newBackup := strings.Replace(name, ".json", fmt.Sprintf(".%s.json", newerBackupTag), 1)
		t.Run("backup removal "+filepath.Base(oldBackup), func(t *testing.T) {
			_, err = os.Stat(oldBackup)
			assert.True(t, os.IsNotExist(err))
			_, err = os.Stat(newBackup)
			assert.Nil(t, err)
		})
	}
}

func TestSaveWithTargetTree(t *testing.T) {
	repoDir, files, err := createMockRepo(testFilePaths)
	require.Nil(t, err)
	defer os.RemoveAll(repoDir)

	repo, err := newLocalRepo(repoDir)
	require.Nil(t, err)
	root, err := repo.root()
	require.Nil(t, err)
	snapshot, err := repo.snapshot()
	require.Nil(t, err)
	timestamp, err := repo.timestamp()
	targets, err := repo.targets(&localTargetFetcher{repoDir})
	require.Nil(t, err)

	// get rid of files so we can check if they got saved
	for _, file := range files {
		err = os.Remove(file)
		require.Nil(t, err)
	}
	// get rid of the targets dir to test dir creation
	err = os.RemoveAll(filepath.Join(repoDir, "targets"))
	assert.Nil(t, err)

	ss := saveSettings{
		tufRepositoryRootDir: repoDir,
		backupAge:            defaultBackupAge,
		rootRole:             root,
		snapshotRole:         snapshot,
		timestampRole:        timestamp,
		targetsRole:          targets,
	}

	err = saveTufRepository(&ss)
	require.Nil(t, err)

	for _, file := range files {
		_, err = os.Stat(file)
		assert.Nil(t, err, "missing save "+file)
	}
	ss.tufRepositoryRootDir = ss.tufRepositoryRootDir + "xxx"

	err = saveTufRepository(&ss)
	require.NotNil(t, err)
}
