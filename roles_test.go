package updater

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetsJson(t *testing.T) {
	buff, err := test.Asset("test/data/targets.json")
	require.Nil(t, err)
	var targets Targets
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targets)
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
	assert.Equal(t, 3453, target.Length)
	hash, ok := target.Hashes[hashSHA256]
	require.True(t, ok)
	assert.Equal(t, "xdD9jvFLoCYvTNYiyDMyX054paEjI88NddSVAv8fZXI=", hash)
	require.Len(t, targets.Signatures, 1)
	sig := targets.Signatures[0]
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, "d24c36bfeb612b6900df04a71a4a8e5a3c9847d3acbc2d27a3ef820895e5d42c", sig.KeyID)
	assert.Equal(t, "XZQ3BgSgdKzdpKd8sDhrfm/PvD4zof2vQNly9/16hgGCU5X882t7Hq5OcdX/Ov6zVKxC0J2LpM+vMIx4HSjGjA==", sig.Value)
}

func TestRootJson(t *testing.T) {
	buff, err := test.Asset("test/data/root.json")
	require.Nil(t, err)
	var root Root
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
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
	assert.Equal(t, "db897a1fb0c62fb8e8a43c5fdd9fd5fbe2c1581b675046a64ff1138902ecdcd7", sig.KeyID)
	assert.Equal(t, methodECDSA, sig.SigningMethod)
	assert.Equal(t, "9ibr3RQubULaF8maMuFbxX3s6dhlOzC7f8lgQ5m9YZpsFBwKLdrmT4Gm96cFQSMml0FkKXGHgabRGA0efsroXA==", sig.Value)
}
