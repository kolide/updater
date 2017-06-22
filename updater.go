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
	"time"

	"github.com/kolide/updater/tuf"
	"github.com/pkg/errors"
)

const backupSubDir = "backup"

type Settings tuf.Settings

// Updater handles software updates for an application
type Updater struct {
	settings            tuf.Settings
	done                chan chan struct{}
	checkFrequency      time.Duration
	notificationHandler NotificationHandler
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

var (
	// ErrCheckFrequency caused by supplying a check frequency that was too small.
	ErrCheckFrequency = fmt.Errorf("frequency value must be %q or greater", minimumCheckFrequency)

	// ErrPackageDoesNotExist the package file does not exist.
	ErrPackageDoesNotExist = errors.New("package file does not exist")
)

// Start creates a new updater. By default the updater will check for updates every hour
// but this may be changed by passing Frequency as an option.  The minimum
// frequency is 1 minute.  Anything less than that will cause an error.
// onUpdate is called when an update needs to be applied and where an application would
// use the update.
func Start(settings Settings, onUpdate NotificationHandler, opts ...Option) (*Updater, error) {
	err := settings.verify()
	if err != nil {
		return nil, errors.Wrap(err, "creating updater")
	}
	updater := Updater{
		checkFrequency:      defaultCheckFrequency,
		notificationHandler: onUpdate,
		settings:            tuf.Settings(settings),
	}
	for _, opt := range opts {
		opt(&updater)
	}
	if updater.checkFrequency < minimumCheckFrequency {
		return nil, ErrCheckFrequency
	}
	go updater.loop()
	return &updater, nil
}

// Stop will disables the update checker goroutine.
func (u *Updater) Stop() {
	done := make(chan struct{})
	u.done <- done
	<-done
}

func (u *Updater) loop() {
	ticker := time.NewTicker(u.checkFrequency).C
	for {
		stagingPath, err := tuf.GetStagedPath(&u.settings)
		if err != nil || stagingPath != "" {
			u.notificationHandler(stagingPath, err)
		}
		select {
		case <-ticker:
		case done := <-u.done:
			close(done)
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
