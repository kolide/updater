package tuf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type localTargetReader struct {
	baseDir string
}

func (rdr *localTargetReader) read(role string) (*Targets, error) {
	f, err := os.Open(filepath.Join(rdr.baseDir, fmt.Sprintf("%s.json", role)))
	if err != nil {
		return nil, errors.Wrap(err, "local target read from file")
	}
	defer f.Close()
	var result Targets
	err = json.NewDecoder(f).Decode(&result)
	if err != nil {
		return nil, errors.Wrap(err, "decoding json reading local target")
	}
	return &result, nil
}

func (r *localRepo) root(opts ...func() interface{}) (*Root, error) {
	var root Root
	err := r.getRole(roleRoot, &root)
	if err != nil {
		return nil, errors.Wrap(err, "getting local root role")
	}
	return &root, nil
}

func (r *localRepo) timestamp() (*Timestamp, error) {
	var ts Timestamp
	err := r.getRole(roleTimestamp, &ts)
	if err != nil {
		return nil, errors.Wrap(err, "getting local timestamp role")
	}
	return &ts, nil
}

func (r *localRepo) snapshot(opts ...func() interface{}) (*Snapshot, error) {
	var ss Snapshot
	err := r.getRole(roleSnapshot, &ss)
	if err != nil {
		return nil, errors.Wrap(err, "getting local snapshot role")
	}
	return &ss, nil
}

func (r *localRepo) targets(rdr roleReader, opts ...func() interface{}) (*RootTarget, error) {
	trg, err := getTargetRole(rdr)
	if err != nil {
		return nil, errors.Wrap(err, "getting local targets role")
	}
	return trg, nil
}

// save persists role information, r is the role type, and
// data is the class containing the role information
func (r *localRepo) save(roleName role, data interface{}) error {
	isRoleCorrect(roleName, data)
	f, err := os.OpenFile(filepath.Join(r.repoPath, fmt.Sprintf("%s.json", roleName)), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "opening role file for writing")
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(data)
}

func (r *localRepo) getRole(name role, val interface{}) error {
	err := validateRole(name)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(r.repoPath, fmt.Sprintf("%s.json", name)))
	if err != nil {
		return errors.Wrap(err, "getting role")
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(val)
}
