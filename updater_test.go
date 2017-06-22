package updater

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	fakeDir, _ := os.Getwd()
	settings := Settings{
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

	u, err = New(settings, onUpdate, WithFrequency(minimumCheckFrequency-time.Second))
	assert.Equal(t, ErrCheckFrequency, err)
	assert.Nil(t, u)

	u, err = New(settings,
		onUpdate,
		WithFrequency(minimumCheckFrequency+time.Second),
	)
	assert.Nil(t, err)
	require.NotNil(t, u)
	assert.NotNil(t, u.notificationHandler)
}

func TestSettingsVerification(t *testing.T) {
	var s Settings
	err := s.verify()
	assert.NotNil(t, err)

	s.GUN = "kolide/agent/linux"
	s.LocalRepoPath, _ = os.Getwd()
	s.StagingPath, _ = os.Getwd()
	s.MirrorURL = "https://mirror.com"
	s.RemoteRepoBaseURL = "https://notary.com"
	s.TargetName = "sometarget"
	err = s.verify()
	assert.Nil(t, err)

	s.LocalRepoPath = ""
	err = s.verify()
	assert.NotNil(t, err)

}
