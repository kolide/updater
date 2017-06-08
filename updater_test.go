package updater

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpdater(t *testing.T) {
	wd, _ := os.Getwd()
	settings := UpdateSettings{
		BaseDir:      path.Join(wd, "base"),
		RepositoryID: "acme/someprogram/linux",
	}
	u, err := NewUpdater(&settings)
	require.Nil(t, err)
	require.NotNil(t, u)
	defer u.Close()
	defer os.RemoveAll(settings.BaseDir)
	stat, err := os.Stat(path.Join(settings.BaseDir, osPath(settings.RepositoryID), "status"))
	require.Nil(t, err)
	assert.NotNil(t, stat)
}

func TestNewUpdaterWithExistingBase(t *testing.T) {
	wd, _ := os.Getwd()
	settings := UpdateSettings{
		BaseDir:      path.Join(wd, "base"),
		RepositoryID: "acme/someprogram/linux",
	}
	err := os.MkdirAll(settings.BaseDir, 0755)
	require.Nil(t, err)
	defer os.RemoveAll(settings.BaseDir)
	u, err := NewUpdater(&settings)
	require.Nil(t, err)
	require.NotNil(t, u)
	defer u.Close()
	stat, err := os.Stat(path.Join(settings.BaseDir, osPath(settings.RepositoryID), "status"))
	require.Nil(t, err)
	assert.NotNil(t, stat)

}
