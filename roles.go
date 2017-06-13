package updater

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

// Root is the root role
type Root struct {
	Signed     SignedRoot  `json:"signed"`
	Signatures []Signature `json:"signatures"`
}

type SignedRoot struct {
	Type               string        `json:"_type"`
	ConsistentSnapshot bool          `json:"consistent_snapshot"`
	Expires            time.Time     `json:"expires"`
	Keys               map[keyID]Key `json:"keys"`
	Roles              map[role]Role
	Version            int `json:"version"`
}

// Targets represents TUF role of the same name
// See https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
type Targets struct {
	Signed     TargetSigned `json:"signed"`
	Signatures []Signature  `json:"signatures"`
}

// TargetSigned specifics of the Targets
type TargetSigned struct {
	Type        string                `json:"_type"`
	Delegations Delegations           `json:"delegations"`
	Expires     time.Time             `json:"expires"`
	Targets     map[targetPath]Target `json:"targets"`
	Version     int                   `json:"version"`
}

// Signature information to validate digital signatures
type Signature struct {
	KeyID         string `json:"keyid"`
	SigningMethod string `json:"method"`
	Value         string `json:"sig"`
}

// Target signing information
type Target struct {
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
