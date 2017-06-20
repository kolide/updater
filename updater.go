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
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/kolide/updater/tuf"
	"github.com/pkg/errors"
)

// EventType classifies errors that occur in the update process
type EventType int

const (
	// InfoType indicates event is routine
	InfoType EventType = iota
	ErrorType
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

// Event information about an update
type Event struct {
	Time        time.Time
	Description string
	Type        EventType
}

// Events information about a update cycle
type Events struct {
	History []Event
}

func (evts *Events) push(evtType EventType, format string, args ...interface{}) {
	evts.History = append(evts.History, Event{time.Now(), fmt.Sprintf(format, args...), evtType})
}

// NotificationHandler will be invoked when the updater runs. Events describing
// that status of the update will be collected in Events.
type NotificationHandler func(evts Events)

const defaultCheckFrequency = 1 * time.Hour
const minimumCheckFrequency = 10 * time.Minute

// ErrCheckFrequency caused by supplying a check frequency that was too small.
var ErrCheckFrequency = fmt.Errorf("Frequency value must be %q or greater", minimumCheckFrequency)

// ErrPackageDoesNotExist the package file does not exist
var ErrPackageDoesNotExist = fmt.Errorf("package file does not exist")

// New creates a new updater. exeCmd is the required cmd for the executable file
// hosting the updater package. By default the updater will check for updates every hour
// but this may be changed by passing Frequency as an option.  The minimum
// frequency is 10 minutes.  Anything less than that will cause an error.
// Supply the WantNotfications option to get logging information about updates.
func New(settings tuf.Settings, exeCmd exec.Cmd, opts ...func() interface{}) (*Updater, error) {
	err := settings.Verify()
	if err != nil {
		return nil, errors.Wrap(err, "creating updater")
	}
	updater := Updater{
		checkFrequency: defaultCheckFrequency,
		cmd:            exeCmd,
	}
	for _, opt := range opts {
		switch t := opt().(type) {
		case updateDuration:
			updater.checkFrequency = time.Duration(t)
		case NotificationHandler:
			updater.notificationHandler = t
		}
	}
	if updater.checkFrequency < minimumCheckFrequency {
		return nil, ErrCheckFrequency
	}
	return &updater, nil
}

type updateDuration time.Duration

// Frequency allows changing the frequency of update checks by passing
// this method to update.New
func Frequency(duration time.Duration) func() interface{} {
	return func() interface{} {
		return updateDuration(duration)
	}
}

// WantNotifications is used to pass a function that will collect information about updates.
func WantNotifications(hnd NotificationHandler) func() interface{} {
	return func() interface{} {
		return hnd
	}
}

// Start begins checking for updates.
func (u *Updater) Start() {
	u.ticker = time.NewTicker(u.checkFrequency)
	u.done = make(chan struct{})
	go updater(u.settings, u.cmd, u.ticker.C, u.done, u.notificationHandler)
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

func updater(settings tuf.Settings, cmd exec.Cmd, ticker <-chan time.Time, done <-chan struct{}, notifications NotificationHandler) {
	select {
	case <-ticker:
		update(settings, cmd, notifications)
	case <-done:
		return
	}
}

func update(settings tuf.Settings, cmd exec.Cmd, notifications NotificationHandler) {
	var events Events
	defer func() {
		if notifications != nil {
			notifications(events)
		}
	}()

	events.push(InfoType, "start check for updates")
	// get pending updates, the validity of package signatures in the updates
	// are checked before they are returned.
	updates, err := tuf.GetStagedPaths(&settings)
	if err != nil {
		events.push(ErrorType, "Error getting updates %q", err)
		return
	}
	// Prepare to install by copying the current install into a backup directory.
	// We expect the install program to write it's changes into the install directory. If
	// something fails, we replace the modified install directory with it's original
	// contents.
	backupDirectory, err := backup(settings.InstallDir, settings.StagingPath)
	if err != nil {
		events.push(ErrorType, "Could not create application backup")
		return
	}
	var successfulUpdates []string
	for _, updatePackagePath := range updates {
		events.push(InfoType, "start update with package %q", updatePackagePath)
		err = applyUpdate(updatePackagePath)
		if err != nil {
			events.push(ErrorType, "applying update error %q", err)
		}
		events.push(InfoType, "updated %q", updatePackagePath)
		successfulUpdates = append(successfulUpdates, updatePackagePath)
	}

	if len(successfulUpdates) < len(updates) {
		events.push(ErrorType, "%d of %d updates succeeded, rolling back", len(successfulUpdates), len(updates))
		err = rollback(backupDirectory, settings.InstallDir)
		if err != nil {
			events.push(ErrorType, "rollback failed")
		}
		return
	}
	events.push(InfoType, "updates complete")
	if len(updates) > 0 && len(updates) == len(successfulUpdates) {
		restart(cmd)
	}
}

// Backs up contents of the install directory, and symlinks in the
// install directory tree are not followed.
func backup(installPath, stagingPath string) (string, error) {
	backupSubDir := path.Join(stagingPath, backupSubDir, tuf.GetTag())
	err := os.MkdirAll(backupSubDir, 0744)
	if err != nil {
		return "", errors.Wrap(err, "creating backup directory")
	}
	err = copyRecursive(installPath, backupSubDir)
	if err != nil {
		return "", errors.Wrap(err, "backing up installation files")
	}
	return backupSubDir, nil
}

func rollback(backupPath, installPath string) error {
	err := os.RemoveAll(installPath)
	if err != nil {
		return errors.Wrap(err, "removing bad install")
	}
	err = os.Rename(backupPath, installPath)
	if err != nil {
		return errors.Wrap(err, "replacing old install")
	}
	return nil
}

func applyUpdate(updatePackagePath string) error {
	// each update is an executable that does stuff
	// it could be as simple as updating some config files, or
	// it could update the agent and restart it
	_, err := os.Stat(updatePackagePath)
	if os.IsNotExist(err) {
		return ErrPackageDoesNotExist
	}
	if err != nil {
		return errors.Wrap(err, "checking for package existance")
	}
	// file exists change to executable
	err = os.Chmod(updatePackagePath, 0744)
	if err != nil {
		return errors.Wrap(err, "setting package to executable")
	}
	cmd := exec.Command(updatePackagePath)
	// execute update package and wait for it to complete
	return cmd.Run()
}
