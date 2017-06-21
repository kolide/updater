package updater

import (
	"os"
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
		StagingPath:       fakeDir,
		MirrorURL:         "https://mirror.com",
		RemoteRepoBaseURL: "https://notary.com",
		TargetName:        "latest",
	}
	onUpdate := func(stagingPath string, err error) {}

	u, err := New(settings, onUpdate)
	require.Nil(t, err)
	assert.Equal(t, defaultCheckFrequency, u.checkFrequency)

	u, err = New(settings, onUpdate, Frequency(9*time.Minute))
	assert.Equal(t, ErrCheckFrequency, err)
	assert.Nil(t, u)

	u, err = New(settings,
		onUpdate,
		Frequency(601*time.Second),
	)
	assert.Nil(t, err)
	require.NotNil(t, u)
	assert.NotNil(t, u.notificationHandler)
}
