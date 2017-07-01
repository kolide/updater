package tuf

////////////////////////////////////////////////////////////////////////////////
// Methods in this file are used to save and backup the TUF repository
////////////////////////////////////////////////////////////////////////////////
import (
	"bytes"
	"fmt"
	"io"
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

func backupTUFRepo(tufRoot, tag string) error {
	err := checkForDirectoryPresence(tufRoot)
	if err != nil {
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
				if err := copy(oldPath, newPath); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func restoreTUFRepo(tufRoot, tag string) error {
	err := checkForDirectoryPresence(tufRoot)
	if err != nil {
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
				if err := copy(oldPath, newPath); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// remove backups older than age
func removeAgedBackups(tufRoot string, age time.Duration) error {
	err := checkForDirectoryPresence(tufRoot)
	if err != nil {
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
					err = os.Remove(path)
					if err != nil {
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

func saveTufRepository(ss *saveSettings) (err error) {
	tag := time.Now().UTC().Format(time.Now().Format(backupFileTimeTagFormat))
	err = removeAgedBackups(ss.tufRepositoryRootDir, ss.backupAge)
	if err != nil {
		return errors.Wrap(err, "saving roles")
	}
	err = backupTUFRepo(ss.tufRepositoryRootDir, tag)
	if err != nil {
		return errors.Wrap(err, "saving roles")
	}
	defer func() {
		if err != nil {
			restoreTUFRepo(ss.tufRepositoryRootDir, tag)
		}
	}()

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

	for i, delegate := range ss.targetsRole.targetPrecedence {
		// The first Target will always be the root target, which we've
		// already written to file.
		if i == 0 {
			continue
		}
		err = saveRole(ss.tufRepositoryRootDir, delegate.delegateRole, delegate)
		if err != nil {
			return errors.Wrapf(err, "failed to save delegate %q", delegate.delegateRole)
		}
	}
	return nil
}

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
	f, err := os.OpenFile(rolePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "opening file to save role")
	}
	defer f.Close()
	written, err := io.Copy(f, bytes.NewBuffer(buff))
	if err != nil {
		return errors.Wrap(err, "writing role to tuf repo")
	}
	if written != int64(len(buff)) {
		errors.New("incomplete write of role to file")
	}
	return nil
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
