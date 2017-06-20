package tuf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/pkg/errors"
)

// targetPath is the path to the target. Mirror host + targetPath is the
// download location of the file. For example if the mirror is https://releases.kolide.co
// and the targetPath is kolide/agent/linux/installer then you'd download
// https://releases.kolide.co/kolide/agent/linux/installer
type targetPath string
type keyID string
type hashingMethod string
type role string
type signingMethod string

const (
	// Signing Methods
	methodRSA     signingMethod = "rsa"
	methodED25519 signingMethod = "ed25519"
	methodECDSA   signingMethod = "ecdsa"
	// Roles
	roleRoot      role = "root"
	roleSnapshot  role = "snapshot"
	roleTargets   role = "targets"
	roleTimestamp role = "timestamp"

	// Key Types
	keyTypeRSAx509   = "rsa-x509"
	keyTypeECDSA     = "ecdsa"
	keyTypeECDSAx509 = "ecdsa-x509"
	keyTypeED25519   = "ed25519"

	hashSHA256 hashingMethod = "sha256"
	hashSHA512 hashingMethod = "sha512"

	filetimeFormat = "20060102150405"
)

type marshaller interface {
	canonicalJSON() ([]byte, error)
}

type base64decoder interface {
	base64Decoded() ([]byte, error)
}

type keyfinder interface {
	keyMap() map[keyID]Key
}

type keyed interface {
	keys() map[keyID]Key
}
type signed interface {
	sigs() []Signature
}
type signedkeyed interface {
	keyed
	signed
}

// Root is the root role. It indicates
// which keys are authorized for all top-level roles, including the root
// role itself.
type Root struct {
	Signed     SignedRoot  `json:"signed"`
	Signatures []Signature `json:"signatures"`
}

// Keys get key map for root role
func (r *Root) keys() map[keyID]Key {
	return r.Signed.Keys
}

// Sigs get signatures for root role
func (r *Root) sigs() []Signature {
	return r.Signatures
}

// SignedRoot signed contents of the root role
type SignedRoot struct {
	Type               string        `json:"_type"`
	ConsistentSnapshot bool          `json:"consistent_snapshot"`
	Expires            time.Time     `json:"expires"`
	Keys               map[keyID]Key `json:"keys"`
	Roles              map[role]Role `json:"roles"`
	Version            int           `json:"version"`
}

func (sr SignedRoot) canonicalJSON() ([]byte, error) {
	return cjson.MarshalCanonical(sr)
}

// Snapshot is the snapshot role. It lists the version
// numbers of all metadata on the repository, excluding timestamp.json and
// mirrors.json.
type Snapshot struct {
	Signed     SignedSnapshot `json:"signed"`
	Signatures []Signature    `json:"signatures"`
}

// SignedSnapshot is the signed portion of the snapshot
type SignedSnapshot struct {
	Type    string                     `json:"_type"`
	Expires time.Time                  `json:"expires"`
	Version int                        `json:"version"`
	Meta    map[role]FileIntegrityMeta `json:"meta"`
}

func (sr SignedSnapshot) canonicalJSON() ([]byte, error) {
	return cjson.MarshalCanonical(sr)
}

// Timestamp role indicates the latest versions of other files and is frequently resigned to limit the
// amount of time a client can be kept unaware of interference with obtaining updates.
type Timestamp struct {
	Signed     SignedTimestamp `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

// SignedTimestamp signed portion of timestamp role.
type SignedTimestamp struct {
	Type    string                     `json:"_type"`
	Expires time.Time                  `json:"expires"`
	Version int                        `json:"version"`
	Meta    map[role]FileIntegrityMeta `json:"meta"`
}

func (sr SignedTimestamp) canonicalJSON() ([]byte, error) {
	return cjson.MarshalCanonical(sr)
}

// Targets represents TUF role of the same name.
// See https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
type Targets struct {
	Signed     SignedTarget `json:"signed"`
	Signatures []Signature  `json:"signatures"`
}

// SignedTarget specifics of the Targets
type SignedTarget struct {
	Type        string                           `json:"_type"`
	Delegations Delegations                      `json:"delegations"`
	Expires     time.Time                        `json:"expires"`
	Targets     map[targetPath]FileIntegrityMeta `json:"targets"`
	Version     int                              `json:"version"`
}

func (sr SignedTarget) canonicalJSON() ([]byte, error) {
	return cjson.MarshalCanonical(sr)
}

// Signature information to validate digital signatures
type Signature struct {
	KeyID         keyID         `json:"keyid"`
	SigningMethod signingMethod `json:"method"`
	Value         string        `json:"sig"`
}

func (sig *Signature) base64Decoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(sig.Value)
}

// FileIntegrityMeta hashes and length of a file based resource to help ensure
// the binary footprint of the file hasn't been tampered with
type FileIntegrityMeta struct {
	Hashes map[hashingMethod]string `json:"hashes"`
	Length int                      `json:"length"`
}

func (fim FileIntegrityMeta) verify(target []byte, size int64) error {
	if size != int64(fim.Length) {
		return errors.New("target length is incorrect")
	}
	for algo, hash := range fim.Hashes {
		decoded, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return errors.Wrap(err, "failed to decode hash")
		}
		var hashFunc func(b []byte) []byte
		switch algo {
		case hashSHA256:
			hashFunc = func(b []byte) []byte {
				result := sha256.Sum256(b)
				return result[:]
			}
		case hashSHA512:
			hashFunc = func(b []byte) []byte {
				result := sha512.Sum512(b)
				return result[:]
			}
		default:
			return errors.Errorf("unsupported hash algorithm %q", algo)
		}
		targetHash := hashFunc(target)
		if !bytes.Equal(decoded, targetHash) {
			return errors.New("hash mismatch")
		}
	}
	return nil
}

// Delegations signing information for targets hosted by external principals
type Delegations struct {
	Keys  map[keyID]Key    `json:"keys"`
	Roles []DelegationRole `json:"roles"`
}

// Role maps keys in role that are needed to check signatures.
type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

// DelegationRole contains information about targets delegated to other mirrors.
type DelegationRole struct {
	Role
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

// Key signing key with key type
type Key struct {
	KeyType string `json:"keytype"`
	KeyVal  KeyVal `json:"keyval"`
}

// we only really care about the public key
func (k *Key) base64Decoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(k.KeyVal.Public)
}

// KeyVal the contents of the private and/or public keys
type KeyVal struct {
	Private *string `json:"private"`
	Public  string  `json:"public"`
}