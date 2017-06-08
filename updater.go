package updater

import (
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
)

// Updater exposes methods for this package
type Updater struct {
	statusFile *os.File
}

// UpdateSettings settings that define remote repository
type UpdateSettings struct {
	// BaseURL is the url of the notary server
	BaseURL string
	// RepositoryID is the Globally Unique Name (GUN) for this repo. The GUN
	// should be of the form <root>/<project>/<platform>
	RepositoryID string
	// BaseDir is the location for the local cached repository.  The process must
	// have read and write permissions to this location.
	BaseDir string
	// PackageURL is the base url where distribution package is stored
	PackageURL string
}

// NewUpdater creates an Updater with UpdateSettings
func NewUpdater(settings *UpdateSettings) (*Updater, error) {
	var updater Updater
	repoPath := path.Join(settings.BaseDir, osPath(settings.RepositoryID))
	err := updater.maybeCreateDir(repoPath)
	if err != nil {
		return nil, errors.Wrap(err, "creating new updater")
	}
	return &updater, nil
}

// Close frees up Updater resources
func (u *Updater) Close() error {
	if u.statusFile != nil {
		return u.statusFile.Close()
	}
	return nil
}

func (u *Updater) maybeCreateDir(dir string) error {
	status, err := os.Stat(dir)
	if os.IsNotExist(err) {
		// Create directory, the base directory is for the local notary repo,
		// the full directory is for project specific files.
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrap(err, "creating repository directory")
		}
	}
	if status != nil && !status.IsDir() {
		return errors.Errorf("%s is not a directory", dir)
	}
	// Create status file to keep track of updates
	statusFile := path.Join(dir, "status")
	u.statusFile, err = os.OpenFile(statusFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return errors.Wrap(err, "creating status file")
	}
	return nil
}

func osPath(dir string) string {
	parts := strings.Split(dir, "/")
	return path.Join(parts...)
}
