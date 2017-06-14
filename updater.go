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

// Updater handles software updates for an application
type Updater struct {
	ticker              *time.Ticker
	settings            tuf.Settings
	checkFrequency      time.Duration
	notificationHandler NotificationHandler
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

// ErrPackageDoesNotExit the package file does not exist
var ErrPackageDoesNotExit = fmt.Errorf("package file does not exist")

// New creates a new updater. By default the updater will check for updates every hour
// but this may be changed by passing Frequency as an option.  The minimum
// frequency is 10 minutes.  Anything less than that will cause an error.
// Supply the WantNotfications option to get data on the state up update operations for
// logging.
func New(settings tuf.Settings, opts ...func() interface{}) (*Updater, error) {
	updater := Updater{
		checkFrequency: defaultCheckFrequency,
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

// WantNotfications pass a function that will collect information about updates.
func WantNotfications(hnd NotificationHandler) func() interface{} {
	return func() interface{} {
		return hnd
	}
}

// Start begins checking for updates.
func (u *Updater) Start() {
	u.ticker = time.NewTicker(u.checkFrequency)
	go updater(u.settings, u.ticker.C, u.notificationHandler)
}

// Stop will disable update checks
func (u *Updater) Stop() {
	if u.ticker != nil {
		u.ticker.Stop()
	}
}

func updater(settings tuf.Settings, ticker <-chan time.Time, notifications NotificationHandler) {
	for _ = range ticker {
		update(settings, notifications)
	}
}

func update(settings tuf.Settings, notifications NotificationHandler) {
	var events Events
	defer func() {
		if notifications != nil {
			notifications(events)
		}
	}()

	events.push(InfoType, "start check for updates")
	// get pending updates
	updates, err := tuf.GetStagedPaths(&settings)
	if err != nil {
		events.push(ErrorType, "Error getting updates %q", err)
		if notifications != nil {
			return
		}
	}
	var successfulUpdates []string
	for _, updatePackagePath := range updates {
		events.push(InfoType, "start update with package %q", updatePackagePath)
		err = applyUpdate(updatePackagePath)
		if err != nil {
			events.push(ErrorType, "applying update error %q", err)
			break
		}
		events.push(InfoType, "updated %q", updatePackagePath)
		successfulUpdates = append(successfulUpdates, updatePackagePath)
	}

	if len(successfulUpdates) < len(updates) {
		events.push(ErrorType, "%d of %d updates succeeded, rolling back", len(successfulUpdates), len(updates))
		// rollback in reverse order
		for i := len(successfulUpdates) - 1; i >= 0; i-- {
			err = applyRollback(successfulUpdates[i])
			if err != nil {
				events.push(ErrorType, "rollback failed %q", successfulUpdates[i])
			}
			events.push(InfoType, "rollback succeeded %q", successfulUpdates[i])
		}
	}
	events.push(InfoType, "updates complete")
	if len(updates) > 0 && len(updates) == len(successfulUpdates) {
		restart()
	}
}

func applyRollback(updatePackagePath string) error {
	_, err := os.Stat(updatePackagePath)
	if os.IsNotExist(err) {
		return ErrPackageDoesNotExit
	}
	cmd := exec.Command(updatePackagePath, "-rollback")
	return cmd.Run()
}

func applyUpdate(updatePackagePath string) error {
	// each update is an executable that does stuff
	// it could be as simple as updating some config files, or
	// it could update the agent and restart it
	_, err := os.Stat(updatePackagePath)
	if os.IsNotExist(err) {
		return ErrPackageDoesNotExit
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
