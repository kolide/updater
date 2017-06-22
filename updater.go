// Package updater is included in a program to provide secure, automated updates. The
// updater uses Notary and the TUF frame work to facilitate secure updates.  The update
// packages are mirrored on a remote location such as Google Cloud Storage. When updater
// is created it checks with Notary to see if there are any new updates to apply. If
// there are, each update will be applied.  If any of the updates fail, previous successful
// updates are rolled back.
//
// See TUF Spec https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
//
// See Notary https://github.com/docker/notary
package updater

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/kolide/updater/tuf"
	"github.com/pkg/errors"
)

const backupSubDir = "backup"

// Updater handles software updates for an application
type Updater struct {
	ticker              *time.Ticker
	done                chan struct{}
	settings            tuf.Settings
	checkFrequency      time.Duration
	notificationHandler NotificationHandler
	cmd                 exec.Cmd
}

// NotificationHandler gets called when the hosting application has a new version
// of a target that it needs to deal with.  The hosting application will need to
// check the err object, if err is nil the stagingPath will point to a validated
// target which is the hosting application's responsibility to deal with.
type NotificationHandler func(stagingPath string, err error)

const defaultCheckFrequency = 1 * time.Hour
const minimumCheckFrequency = 1 * time.Minute

// ErrCheckFrequency caused by supplying a check frequency that was too small.
var ErrCheckFrequency = fmt.Errorf("Frequency value must be %q or greater", minimumCheckFrequency)

// ErrPackageDoesNotExist the package file does not exist
var ErrPackageDoesNotExist = fmt.Errorf("package file does not exist")

// Optional New Parameter(s)
type updateDuration time.Duration

// Frequency allows changing the frequency of update checks by passing
// this method to update.New
func Frequency(duration time.Duration) func() interface{} {
	return func() interface{} {
		return updateDuration(duration)
	}
}

// New creates a new updater.  By default the updater will check for updates every hour
// but this may be changed by passing Frequency as an option.  The minimum
// frequency is 1 minute.  Anything less than that will cause an error.
// onUpdate is called when an update needs to be applied and where an application would
// use the update.
func New(settings tuf.Settings, onUpdate NotificationHandler, opts ...func() interface{}) (*Updater, error) {
	err := settings.Verify()
	if err != nil {
		return nil, errors.Wrap(err, "creating updater")
	}
	updater := Updater{
		checkFrequency:      defaultCheckFrequency,
		notificationHandler: onUpdate,
		settings:            settings,
	}
	for _, opt := range opts {
		switch t := opt().(type) {
		case updateDuration:
			updater.checkFrequency = time.Duration(t)
		}
	}
	if updater.checkFrequency < minimumCheckFrequency {
		return nil, ErrCheckFrequency
	}
	return &updater, nil
}

// Start begins checking for updates.
func (u *Updater) Start() {
	u.ticker = time.NewTicker(u.checkFrequency)
	u.done = make(chan struct{})
	go updater(u.settings, u.ticker.C, u.done, u.notificationHandler)
}

// Stop will disable update checks
func (u *Updater) Stop() {
	if u.ticker != nil {
		u.ticker.Stop()
	}
	if u.done != nil {
		u.done <- struct{}{}
	}
}

func updater(settings tuf.Settings, ticker <-chan time.Time, done <-chan struct{}, notifications NotificationHandler) {
	for {
		// run right away
		stagingPath, err := tuf.GetStagedPath(&settings)
		if err != nil || stagingPath != "" {
			notifications(stagingPath, err)
		}
		select {
		case <-ticker:
		case <-done:
			return
		}
	}
}
