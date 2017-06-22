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

type Settings tuf.Settings

// Updater handles software updates for an application
type Updater struct {
	ticker              *time.Ticker
	done                chan struct{}
	settings            Settings
	checkFrequency      time.Duration
	notificationHandler NotificationHandler
	cmd                 exec.Cmd
}

// WithFrequency allows changing the frequency of update checks.
func WithFrequency(duration time.Duration) Option {
	return func(u *Updater) {
		u.checkFrequency = duration
	}
}

// Option defines a way to provide optional arguments when creating a new Updater.
type Option func(*Updater)

// NotificationHandler gets called when the hosting application has a new version
// of a target that it needs to deal with.  The hosting application will need to
// check the err object, if err is nil the stagingPath will point to a validated
// target which is the hosting application's responsibility to deal with.
type NotificationHandler func(stagingPath string, err error)

const (
	defaultCheckFrequency = 1 * time.Hour
	minimumCheckFrequency = 1 * time.Minute
)

// ErrCheckFrequency caused by supplying a check frequency that was too small.
var ErrCheckFrequency = fmt.Errorf("Frequency value must be %q or greater", minimumCheckFrequency)

// ErrPackageDoesNotExist the package file does not exist
var ErrPackageDoesNotExist = fmt.Errorf("package file does not exist")

// New creates a new updater.  By default the updater will check for updates every hour
// but this may be changed by passing Frequency as an option.  The minimum
// frequency is 1 minute.  Anything less than that will cause an error.
// onUpdate is called when an update needs to be applied and where an application would
// use the update.
func New(settings Settings, onUpdate NotificationHandler, opts ...Option) (*Updater, error) {
	err := settings.verify()
	if err != nil {
		return nil, errors.Wrap(err, "creating updater")
	}
	updater := Updater{
		checkFrequency:      defaultCheckFrequency,
		notificationHandler: onUpdate,
		settings:            settings,
	}
	for _, opt := range opts {
		opt(&updater)
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

func updater(settings Settings, ticker <-chan time.Time, done <-chan struct{}, notifications NotificationHandler) {
	tufSettings := tuf.Settings(settings)
	for {
		// run right away
		stagingPath, err := tuf.GetStagedPath(&tufSettings)
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

// Verify performs some preliminary checks on parameter.
func (s *Settings) verify() error {
	err := tuf.ValidatePath(s.LocalRepoPath)
	if err != nil {
		return errors.Wrap(err, "verifying local repo path")
	}
	err = tuf.ValidatePath(s.StagingPath)
	if err != nil {
		return errors.Wrap(err, "verifying staging path")
	}
	if s.GUN == "" {
		return errors.New("GUN can't be empty")
	}
	if s.TargetName == "" {
		return errors.New("TargetName can't be empty")
	}
	_, err = tuf.ValidateURL(s.RemoteRepoBaseURL)
	if err != nil {
		return errors.Wrap(err, "remote repo url validation")
	}
	_, err = tuf.ValidateURL(s.MirrorURL)
	if err != nil {
		return errors.Wrap(err, "mirror url validation")
	}
	return nil
}
