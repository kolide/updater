package tuf

import (
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

// FileIntegrityMeta hashes and length of a file based resource to help ensure
// the binary footprint of the file hasn't been tampered with
type FileIntegrityMeta struct {
	Hashes map[hashingMethod]string `json:"hashes"`
	Length int64                    `json:"length"`
}

func newFileIntegrityMeta() *FileIntegrityMeta {
	return &FileIntegrityMeta{
		Hashes: make(map[hashingMethod]string),
	}
}

func (fim FileIntegrityMeta) clone() *FileIntegrityMeta {
	h := make(map[hashingMethod]string)
	for k, v := range fim.Hashes {
		h[k] = v
	}
	return &FileIntegrityMeta{h, fim.Length}
}

// Equal is deep comparison of two FileIntegrityMeta
func (fim FileIntegrityMeta) Equal(fimTarget FileIntegrityMeta) bool {
	if fim.Length != fimTarget.Length {
		return false
	}
	if len(fim.Hashes) != len(fimTarget.Hashes) {
		return false
	}
	for algo, hash := range fim.Hashes {
		h, ok := fimTarget.Hashes[algo]
		if !ok {
			return false
		}
		if h != hash {
			return false
		}
	}
	return true
}

// File hash and length validation per TUF 5.5.2
func (fim FileIntegrityMeta) verify(rdr io.Reader) error {
	var hashes []hashInfo
	for algo, expectedHash := range fim.Hashes {
		var hashFunc hash.Hash
		valid, err := base64.StdEncoding.DecodeString(expectedHash)
		if err != nil {
			return errors.New("invalid hash in verify")
		}
		hashFunc, err = getHasher(algo)
		if err != nil {
			return err
		}
		rdr = io.TeeReader(rdr, hashFunc)
		hashes = append(hashes, hashInfo{hashFunc, valid})
	}
	length, err := io.Copy(ioutil.Discard, rdr)
	if err != nil {
		return err
	}
	if length != fim.Length {
		return errLengthIncorrect
	}
	for _, h := range hashes {
		if subtle.ConstantTimeCompare(h.valid, h.h.Sum(nil)) != 1 {
			return errHashIncorrect
		}
	}
	return nil
}
