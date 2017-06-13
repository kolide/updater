package tuf

import (
	"time"
)

// targetPath is the path to the target. Mirror host + targetPath is the
// download location of the file. For example if the mirror is https://releases.kolide.co
// and the targetPath is agent/v1/linux/installer then you'd download
// https://releases.kolide.co/agent/v1/linux/installer
type targetPath string
type keyID string
type hashingMethod string
type role string

const (
	// Signing Methods
	methodRSA     = "rsa"
	methodED25519 = "ed25519"
	methodECDSA   = "ecdsa"
	// Roles
	roleRoot      role = "root"
	roleSnapshot  role = "snapshot"
	roleTargets   role = "targets"
	roleTimestamp role = "timestamp"

	// Key Types
	keyTypeRSAx509   = "rsa-x509"
	keyTypeECDSA     = "ecdsa"
	keyTypeECDSAx509 = "ecdsa-x509"

	hashSHA256 hashingMethod = "sha256"
	hashSHA512 hashingMethod = "sha512"
)

// Root is the root role. It indicates
// which keys are authorized for all top-level roles, including the root
// role itself.
type Root struct {
	Signed     SignedRoot  `json:"signed"`
	Signatures []Signature `json:"signatures"`
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

// Targets represents TUF role of the same name.
// See https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
type Targets struct {
	Signed     TargetSigned `json:"signed"`
	Signatures []Signature  `json:"signatures"`
}

// TargetSigned specifics of the Targets
type TargetSigned struct {
	Type        string                           `json:"_type"`
	Delegations Delegations                      `json:"delegations"`
	Expires     time.Time                        `json:"expires"`
	Targets     map[targetPath]FileIntegrityMeta `json:"targets"`
	Version     int                              `json:"version"`
}

// Signature information to validate digital signatures
type Signature struct {
	KeyID         string `json:"keyid"`
	SigningMethod string `json:"method"`
	Value         string `json:"sig"`
}

// FileIntegrityMeta hashes and length of a file based resource to help ensure
// the binary footprint of the file hasn't been tampered with
type FileIntegrityMeta struct {
	Hashes map[hashingMethod]string `json:"hashes"`
	Length int                      `json:"length"`
}

// Delegation signing information for targets hosted by external principals
type Delegations struct {
	Keys  map[keyID]Key    `json:"keys"`
	Roles []DelegationRole `json:"roles"`
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

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

// KeyVal the contents of the private and/or public keys
type KeyVal struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}
