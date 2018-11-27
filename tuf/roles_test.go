package tuf

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetsJson(t *testing.T) {
	buff := testAsset(t, "testdata/data/targets.json")
	var targets Targets
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targets)
	require.Nil(t, err)
	key, ok := targets.Signed.Delegations.Keys["894776e7a27799cd2e1f18f988360bd65b75d07488e16009db92102b7ef9b458"]
	require.True(t, ok)
	assert.Regexp(t, regexp.MustCompile(`^LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JS`), key.KeyVal.Public)
	assert.Equal(t, keyTypeRSAx509, key.KeyType)
	assert.Equal(t, string(roleTargets), strings.ToLower(targets.Signed.Type))
	require.Len(t, targets.Signed.Delegations.Roles, 1)
	role := targets.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	assert.Equal(t, "894776e7a27799cd2e1f18f988360bd65b75d07488e16009db92102b7ef9b458", role.KeyIDs[0])
	assert.Equal(t, "targets/releases", role.Name)
	assert.Equal(t, "2020-06-11T16:02:16.180597846-05:00", targets.Signed.Expires.Format(time.RFC3339Nano))
	assert.Equal(t, 5, targets.Signed.Version)
	target, ok := targets.Signed.Targets["1.0.0"]
	require.True(t, ok)
	assert.Equal(t, int64(3453), target.Length)
	hash, ok := target.Hashes[hashSHA256]
	require.True(t, ok)
	assert.Equal(t, "xdD9jvFLoCYvTNYiyDMyX054paEjI88NddSVAv8fZXI=", hash)
	require.Len(t, targets.Signatures, 1)
	sig := targets.Signatures[0]
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, keyID("d24c36bfeb612b6900df04a71a4a8e5a3c9847d3acbc2d27a3ef820895e5d42c"), sig.KeyID)
	assert.Equal(t, "XZQ3BgSgdKzdpKd8sDhrfm/PvD4zof2vQNly9/16hgGCU5X882t7Hq5OcdX/Ov6zVKxC0J2LpM+vMIx4HSjGjA==", sig.Value)
}

func TestRootJson(t *testing.T) {
	buff := testAsset(t, "testdata/data/root.json")
	var root Root
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.Nil(t, err)
	signed := root.Signed
	assert.Equal(t, "2027-06-10T13:25:45.170347322-05:00", signed.Expires.Format(time.RFC3339Nano))
	assert.False(t, signed.ConsistentSnapshot)
	assert.Equal(t, 1, signed.Version)
	assert.Len(t, signed.Roles, 4)
	for _, v := range []role{roleRoot, roleSnapshot, roleTargets, roleTimestamp} {
		r, ok := signed.Roles[v]
		require.True(t, ok)
		assert.Equal(t, 1, r.Threshold)
		for _, kid := range r.KeyIDs {
			_, ok := signed.Keys[keyID(kid)]
			assert.True(t, ok)
		}
	}
	require.Len(t, root.Signatures, 1)
	sig := root.Signatures[0]
	assert.Equal(t, keyID("db897a1fb0c62fb8e8a43c5fdd9fd5fbe2c1581b675046a64ff1138902ecdcd7"), sig.KeyID)
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, "9ibr3RQubULaF8maMuFbxX3s6dhlOzC7f8lgQ5m9YZpsFBwKLdrmT4Gm96cFQSMml0FkKXGHgabRGA0efsroXA==", sig.Value)
}

func TestSnapshotJson(t *testing.T) {
	buff := testAsset(t, "testdata/data/snapshot.json")
	var snapshot Snapshot
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&snapshot)
	require.Nil(t, err)
	require.Len(t, snapshot.Signatures, 1)
	sig := snapshot.Signatures[0]
	assert.Equal(t, keyID("cf5d1ca7177c947066404459dcdbfdfed1b684e7cd00d89ed7e513f108df3982"), sig.KeyID)
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, "Pqth0PIvWkYWfgZ1kRVhfa920AAtoujVQePy/HvP9hCS7vGMwrlWX+doDQxiU8Wtdk8WpIgJpYNxui2rF4rNEw==", sig.Value)
	signed := snapshot.Signed
	tt := []struct {
		present bool
		role    role
		sha256  string
		sha512  string
		length  int64
	}{
		{true, roleRoot, `hmw3Q5sat`, `EU+fVRkpw9n1UIzx1`, 2357},
		{true, roleTargets, `nwg+cF2+A+Ybf`, `GGye6UL/7r+qz`, 727},
		{false, roleSnapshot, "", "", 0},
		{false, roleTimestamp, "", "", 0},
	}
	for _, ts := range tt {
		meta, ok := signed.Meta[ts.role]
		assert.Equal(t, ok, ts.present)
		if ok {
			assert.Contains(t, meta.Hashes[hashSHA256], ts.sha256)
			assert.Contains(t, meta.Hashes[hashSHA512], ts.sha512)
			assert.Equal(t, ts.length, meta.Length)
		}
	}
	assert.Equal(t, 4, signed.Version)
}

func TestTimestampJson(t *testing.T) {
	buff := testAsset(t, "testdata/data/timestamp.json")
	var ts Timestamp
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&ts)
	require.Nil(t, err)
	require.Len(t, ts.Signatures, 1)
	sig := ts.Signatures[0]
	assert.Equal(t, keyID("1b52d9751b119e2567dcc3ad68a8f99ccff2ba727d354c74173338133aeb3f87"), sig.KeyID)
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, "92b83fCK0Ozy6y5SUzzBEVeWvcQjf8MwK0nbKu6nZ3NKwOEcW1nn1ZKkwNihn9CePvCZaVlTMnltDoN9/W6ByA==", sig.Value)
	signed := ts.Signed
	tt := []struct {
		present bool
		role    role
		sha256  string
		sha512  string
		length  int64
	}{
		{false, roleRoot, "", "", 0},
		{false, roleTargets, "", "", 0},
		{true, roleSnapshot, `14/Mhpey56v+ADoOpo9mTun`, `6WwFGKoNRKGv+fMfjOnTXmGv2/vzQHwYGmN`, 688},
		{false, roleTimestamp, "", "", 0},
	}
	for _, ts := range tt {
		meta, ok := signed.Meta[ts.role]
		assert.Equal(t, ok, ts.present)
		if ok {
			assert.Contains(t, meta.Hashes[hashSHA256], ts.sha256)
			assert.Contains(t, meta.Hashes[hashSHA512], ts.sha512)
			assert.Equal(t, ts.length, meta.Length)
		}
	}
	assert.Equal(t, 3, signed.Version)
}
