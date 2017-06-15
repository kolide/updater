package updater

import (
	"testing"
	"time"

	"github.com/kolide/updater/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	u, err := New(tuf.Settings{})
	require.Nil(t, err)
	assert.Equal(t, defaultCheckFrequency, u.checkFrequency)

	u, err = New(tuf.Settings{}, Frequency(9*time.Minute))
	assert.Equal(t, ErrCheckFrequency, err)
	assert.Nil(t, u)

	u, err = New(tuf.Settings{},
		Frequency(601*time.Second),
		WantNotifications(func(evt Events) {}),
	)
	assert.Nil(t, err)
	require.NotNil(t, u)
	assert.NotNil(t, u.notificationHandler)

}
