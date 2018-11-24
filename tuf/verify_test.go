package tuf

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ECDSA with x5009ECDSA public key
func TestECDSAx509Verify(t *testing.T) {
	buff := testAsset(t, "testdata/data/root.json")
	var root Root
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.Nil(t, err)
	signed, err := root.Signed.canonicalJSON()
	require.Nil(t, err)
	require.Len(t, root.Signatures, 1)
	sig := root.Signatures[0]
	verifier, err := newVerifier(sig.SigningMethod)
	require.Nil(t, err)
	require.NotNil(t, verifier)
	require.IsType(t, &signingMethodECDSA{}, verifier)
	key, ok := root.Signed.Keys[sig.KeyID]
	require.True(t, ok)
	err = verifier.verify(signed, &key, &sig)
	assert.Nil(t, err)
}

// ECDSA with x509ECDSA public key
func TestECDSAx509VerifyTampered(t *testing.T) {
	buff := testAsset(t, "testdata/data/root.json")
	var root Root
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.Nil(t, err)
	// tamper with object
	role, ok := root.Signed.Roles[roleTimestamp]
	require.True(t, ok)
	role.Threshold = 0
	root.Signed.Roles[roleTimestamp] = role
	signed, err := root.Signed.canonicalJSON()
	require.Nil(t, err)
	require.Len(t, root.Signatures, 1)
	sig := root.Signatures[0]
	verifier, err := newVerifier(sig.SigningMethod)
	require.Nil(t, err)
	require.NotNil(t, verifier)
	require.IsType(t, &signingMethodECDSA{}, verifier)
	key, ok := root.Signed.Keys[sig.KeyID]
	require.True(t, ok)
	err = verifier.verify(signed, &key, &sig)
	require.NotNil(t, err)
	assert.Equal(t, errSignatureCheckFailed, err)
}

func TestECDSAVerify(t *testing.T) {
	buff := testAsset(t, "testdata/data/targets.json")
	var targ Targets
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targ)
	require.Nil(t, err)

	buff = testAsset(t, "testdata/data/root.json")
	var root Root
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	require.Nil(t, err)

	signed, err := targ.Signed.canonicalJSON()
	require.Nil(t, err)
	require.Len(t, targ.Signatures, 1)
	sig := targ.Signatures[0]
	verifier, err := newVerifier(sig.SigningMethod)
	require.Nil(t, err)
	require.NotNil(t, verifier)
	require.IsType(t, &signingMethodECDSA{}, verifier)
	key, ok := root.Signed.Keys[sig.KeyID]
	require.True(t, ok)
	err = verifier.verify(signed, &key, &sig)
	require.Nil(t, err)

	// test invalid key type
	key.KeyType = keyTypeRSAx509
	err = verifier.verify(signed, &key, &sig)
	require.NotNil(t, err)
	assert.Equal(t, errInvalidKeyType, err)
}

func TestHashTesters(t *testing.T) {
	buff := testAsset(t, "testdata/kolide/agent/linux/verify/timestamp.json")
	var ts Timestamp
	err := json.NewDecoder(bytes.NewBuffer(buff)).Decode(&ts)
	require.Nil(t, err)

	snapshot := testAsset(t, "testdata/kolide/agent/linux/verify/snapshot.json")

	ssMeta, ok := ts.Signed.Meta[roleSnapshot]
	require.True(t, ok)

	for algo, expected := range ssMeta.Hashes {
		t.Run(string(algo), func(t *testing.T) {
			hi, err := newHashInfo(algo, []byte(expected))
			require.Nil(t, err)
			require.NotNil(t, hi)
			assert.Implements(t, (*tester)(nil), hi)
			assert.Nil(t, hi.test(snapshot))
		})
	}

}
