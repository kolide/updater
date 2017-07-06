package tuf

////////////////////////////////////////////////////////////////////////////////
// Methods used to save TUF roles that were downloaded from Notary, and rebuilding
// the local TUF repository.  saveTufRepository is the only method called outside
// this file, other methods in this file are called from saveTufRepository.
////////////////////////////////////////////////////////////////////////////////
import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/pkg/errors"
)

const backupFileTimeTagFormat = "20060102150405"

var (
	suffixMatcher = regexp.MustCompile("\\.json$")
	backupMatcher = regexp.MustCompile("\\.[0-9]{14}\\.json$")
)

// Backs up the local TUF repository. If finds all the TUF repository files
// and makes copies of them using a tag which is a timestamp as part of the file name.
// All backup files will have the same tag so we are able to associated a particular
// group/version of backup files.
func backupTUFRepo(tufRoot, tag string) error {
	var err error
	if err = checkForDirectoryPresence(tufRoot); err != nil {
		return err
	}
	return filepath.Walk(tufRoot, func(oldPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			if suffixMatcher.MatchString(oldPath) && !backupMatcher.MatchString(oldPath) {
				base := filepath.Base(oldPath)
				dir := filepath.Dir(oldPath)
				newPath := filepath.Join(dir, strings.Replace(base, ".json", fmt.Sprintf(".%s.json", tag), 1))
				if err = copy(oldPath, newPath); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Restores local TUF repository finding all backup files with a matching tag
// and copying them to normal TUF files.
func restoreTUFRepo(tufRoot, tag string) error {
	var err error
	if err = checkForDirectoryPresence(tufRoot); err != nil {
		return err
	}
	tagMatcher := regexp.MustCompile("\\." + tag + "\\.json$")
	return filepath.Walk(tufRoot, func(oldPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			if tagMatcher.MatchString(oldPath) {
				base := filepath.Base(oldPath)
				dir := filepath.Dir(oldPath)
				newPath := filepath.Join(dir, strings.Replace(base, tag+".json", "json", 1))
				if err = copy(oldPath, newPath); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Remove backups files that are older than the time duration specified by age.
func removeAgedBackups(tufRoot string, age time.Duration) error {
	var err error
	if err = checkForDirectoryPresence(tufRoot); err != nil {
		return err
	}
	if age < 0 {
		return errors.New("age parameter can't be less than zero")
	}
	return filepath.Walk(tufRoot, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			if backupMatcher.MatchString(path) {
				timePart := path[len(path)-19 : len(path)-5]
				backupTime, err := time.Parse(backupFileTimeTagFormat, timePart)
				if err != nil {
					return err
				}
				expirationTime := backupTime.Add(age)
				if time.Now().UTC().After(expirationTime) {
					if err = os.Remove(path); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

type saveSettings struct {
	tufRepositoryRootDir string
	backupAge            time.Duration
	rootRole             *Root
	snapshotRole         *Snapshot
	timestampRole        *Timestamp
	targetsRole          *RootTarget
}

// This function is used to save TUF data downloaded from Notary and save
// it to the local TUF repository.  The function first removes old backups, then
// it creates a new backup of the existing local TUF repo, then it saves the
// TUF data to the local repository, the operation is atomic in that it either
// completely succeeds, or the existing local repository is restored to it's
// original state.
func saveTufRepository(ss *saveSettings) (err error) {
	// Create a timestamp tag to group backup files.
	tag := time.Now().UTC().Format(backupFileTimeTagFormat)
	// See if we have any old backup files hanging around and get rid of them.
	if err = removeAgedBackups(ss.tufRepositoryRootDir, ss.backupAge); err != nil {
		return errors.Wrap(err, "saving roles")
	}
	// Make a new backup of the local TUF repository.
	if err = backupTUFRepo(ss.tufRepositoryRootDir, tag); err != nil {
		return errors.Wrap(err, "saving roles")
	}
	// If something goes wrong restore the local TUF repository to it's original
	// state.
	defer func() {
		if err != nil {
			restoreTUFRepo(ss.tufRepositoryRootDir, tag)
		}
	}()
	// Save each cached notary role to a local file.
	fixedRoles := []struct {
		cached interface{}
		name   role
	}{
		{ss.rootRole, roleRoot},
		{ss.timestampRole, roleTimestamp},
		{ss.snapshotRole, roleSnapshot},
		{ss.targetsRole, roleTargets},
	}
	for _, fixedRole := range fixedRoles {
		if fixedRole.cached == nil {
			return errors.Errorf("required role %q not present", fixedRole.name)
		}
		err = saveRole(ss.tufRepositoryRootDir, string(fixedRole.name), fixedRole.cached)
		if err != nil {
			return errors.Wrap(err, "saving roles")
		}
	}
	// Save each delegate role
	for i, delegate := range ss.targetsRole.targetPrecedence {
		// The first Target will always be the root target, which we've
		// already written to file.
		if i == 0 {
			continue
		}
		if err = saveRole(ss.tufRepositoryRootDir, delegate.delegateRole, delegate); err != nil {
			return errors.Wrapf(err, "failed to save delegate %q", delegate.delegateRole)
		}
	}
	return nil
}

// Saves TUF data to a local repository file. Fixed TUF roles are saved as
// top level files in the repository. Delegate roles are saved in a tree structure.
func saveRole(tufRoot, roleName string, val interface{}) error {
	var fileName string
	if _, ok := val.(*Targets); ok {
		// if it's not a fixed role, we have a delegate so
		// we may have to create nested directories to store data
		fileName = fmt.Sprintf("%s.json", roleName)
		parentDir := filepath.Join(tufRoot, filepath.Dir(roleName))
		_, err := os.Stat(parentDir)
		if os.IsNotExist(err) {
			if err = os.MkdirAll(parentDir, 0755); err != nil {
				return errors.Wrapf(err, "persisting delegate %q", parentDir)
			}
		}
		if err != nil {
			return errors.Wrap(err, "creating parent dir for delegate")
		}
	} else {
		fileName = fmt.Sprintf("%s.json", roleName)
	}
	buff, err := cjson.MarshalCanonical(val)
	if err != nil {
		return errors.Wrap(err, "marshalling role")
	}
	rolePath := filepath.Join(tufRoot, fileName)
	return ioutil.WriteFile(rolePath, buff, 0644)
}

func checkForDirectoryPresence(dir string) error {
	fs, err := os.Stat(dir)
	if err != nil {
		return errors.Wrapf(err, "checking for presence of %q", dir)
	}
	if !fs.IsDir() {
		return errors.Errorf("%q exists but it is not a directory", dir)
	}
	return nil
}

// Platform independent file copy.
func copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return err
}
